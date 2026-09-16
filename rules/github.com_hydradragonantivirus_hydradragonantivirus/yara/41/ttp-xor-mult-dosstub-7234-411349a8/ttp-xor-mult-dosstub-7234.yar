rule TTP_XOR_MULT_DOSStub_7234 {
  strings:
    $key_7234 = { 26 5c [2] 52 44 [2] 15 46 [2] 52 57 [2] 1c 5b [2] 10 51 [2] 07 5a [2] 1c 14 [2] 21 }

  condition:
    any of them
}