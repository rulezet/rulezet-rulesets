rule TTP_XOR_MULT_DOSStub_1442 {
  strings:
    $key_1442 = { 40 2a [2] 34 32 [2] 73 30 [2] 34 21 [2] 7a 2d [2] 76 27 [2] 61 2c [2] 7a 62 [2] 47 }

  condition:
    any of them
}