rule TTP_XOR_MULT_DOSStub_4134 {
  strings:
    $key_4134 = { 15 5c [2] 61 44 [2] 26 46 [2] 61 57 [2] 2f 5b [2] 23 51 [2] 34 5a [2] 2f 14 [2] 12 }

  condition:
    any of them
}