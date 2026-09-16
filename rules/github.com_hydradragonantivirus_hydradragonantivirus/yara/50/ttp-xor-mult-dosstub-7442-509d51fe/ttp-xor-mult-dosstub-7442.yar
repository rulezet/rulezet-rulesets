rule TTP_XOR_MULT_DOSStub_7442 {
  strings:
    $key_7442 = { 20 2a [2] 54 32 [2] 13 30 [2] 54 21 [2] 1a 2d [2] 16 27 [2] 01 2c [2] 1a 62 [2] 27 }

  condition:
    any of them
}