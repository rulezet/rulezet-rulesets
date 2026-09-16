rule TTP_XOR_MULT_DOSStub_1242 {
  strings:
    $key_1242 = { 46 2a [2] 32 32 [2] 75 30 [2] 32 21 [2] 7c 2d [2] 70 27 [2] 67 2c [2] 7c 62 [2] 41 }

  condition:
    any of them
}