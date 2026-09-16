rule TTP_XOR_MULT_DOSStub_e342 {
  strings:
    $key_e342 = { b7 2a [2] c3 32 [2] 84 30 [2] c3 21 [2] 8d 2d [2] 81 27 [2] 96 2c [2] 8d 62 [2] b0 }

  condition:
    any of them
}