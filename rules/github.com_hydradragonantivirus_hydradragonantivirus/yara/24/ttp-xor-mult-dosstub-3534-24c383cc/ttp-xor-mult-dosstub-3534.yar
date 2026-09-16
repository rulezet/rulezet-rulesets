rule TTP_XOR_MULT_DOSStub_3534 {
  strings:
    $key_3534 = { 61 5c [2] 15 44 [2] 52 46 [2] 15 57 [2] 5b 5b [2] 57 51 [2] 40 5a [2] 5b 14 [2] 66 }

  condition:
    any of them
}