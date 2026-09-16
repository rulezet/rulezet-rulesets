rule TTP_XOR_MULT_DOSStub_5542 {
  strings:
    $key_5542 = { 01 2a [2] 75 32 [2] 32 30 [2] 75 21 [2] 3b 2d [2] 37 27 [2] 20 2c [2] 3b 62 [2] 06 }

  condition:
    any of them
}