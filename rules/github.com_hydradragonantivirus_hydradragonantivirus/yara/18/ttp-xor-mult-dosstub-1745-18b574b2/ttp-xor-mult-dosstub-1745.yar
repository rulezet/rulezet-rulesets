rule TTP_XOR_MULT_DOSStub_1745 {
  strings:
    $key_1745 = { 43 2d [2] 37 35 [2] 70 37 [2] 37 26 [2] 79 2a [2] 75 20 [2] 62 2b [2] 79 65 [2] 44 }

  condition:
    any of them
}