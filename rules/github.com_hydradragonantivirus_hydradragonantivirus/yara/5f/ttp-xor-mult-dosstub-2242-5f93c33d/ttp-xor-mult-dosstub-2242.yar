rule TTP_XOR_MULT_DOSStub_2242 {
  strings:
    $key_2242 = { 76 2a [2] 02 32 [2] 45 30 [2] 02 21 [2] 4c 2d [2] 40 27 [2] 57 2c [2] 4c 62 [2] 71 }

  condition:
    any of them
}