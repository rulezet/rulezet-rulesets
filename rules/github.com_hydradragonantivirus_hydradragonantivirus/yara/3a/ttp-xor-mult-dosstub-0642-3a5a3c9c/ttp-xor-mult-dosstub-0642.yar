rule TTP_XOR_MULT_DOSStub_0642 {
  strings:
    $key_0642 = { 52 2a [2] 26 32 [2] 61 30 [2] 26 21 [2] 68 2d [2] 64 27 [2] 73 2c [2] 68 62 [2] 55 }

  condition:
    any of them
}