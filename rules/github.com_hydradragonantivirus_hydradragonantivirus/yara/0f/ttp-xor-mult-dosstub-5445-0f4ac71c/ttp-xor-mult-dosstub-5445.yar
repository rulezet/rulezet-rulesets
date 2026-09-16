rule TTP_XOR_MULT_DOSStub_5445 {
  strings:
    $key_5445 = { 00 2d [2] 74 35 [2] 33 37 [2] 74 26 [2] 3a 2a [2] 36 20 [2] 21 2b [2] 3a 65 [2] 07 }

  condition:
    any of them
}