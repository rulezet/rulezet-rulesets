rule TTP_XOR_MULT_DOSStub_6c42 {
  strings:
    $key_6c42 = { 38 2a [2] 4c 32 [2] 0b 30 [2] 4c 21 [2] 02 2d [2] 0e 27 [2] 19 2c [2] 02 62 [2] 3f }

  condition:
    any of them
}