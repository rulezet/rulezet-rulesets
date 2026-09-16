rule TTP_XOR_MULT_DOSStub_4642 {
  strings:
    $key_4642 = { 12 2a [2] 66 32 [2] 21 30 [2] 66 21 [2] 28 2d [2] 24 27 [2] 33 2c [2] 28 62 [2] 15 }

  condition:
    any of them
}