rule TTP_XOR_MULT_DOSStub_4645 {
  strings:
    $key_4645 = { 12 2d [2] 66 35 [2] 21 37 [2] 66 26 [2] 28 2a [2] 24 20 [2] 33 2b [2] 28 65 [2] 15 }

  condition:
    any of them
}