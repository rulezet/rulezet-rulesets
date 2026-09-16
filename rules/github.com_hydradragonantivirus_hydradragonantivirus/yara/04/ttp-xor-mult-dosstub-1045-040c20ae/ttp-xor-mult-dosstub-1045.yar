rule TTP_XOR_MULT_DOSStub_1045 {
  strings:
    $key_1045 = { 44 2d [2] 30 35 [2] 77 37 [2] 30 26 [2] 7e 2a [2] 72 20 [2] 65 2b [2] 7e 65 [2] 43 }

  condition:
    any of them
}