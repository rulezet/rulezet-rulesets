rule TTP_XOR_MULT_DOSStub_3539 {
  strings:
    $key_3539 = { 61 51 [2] 15 49 [2] 52 4b [2] 15 5a [2] 5b 56 [2] 57 5c [2] 40 57 [2] 5b 19 [2] 66 }

  condition:
    any of them
}