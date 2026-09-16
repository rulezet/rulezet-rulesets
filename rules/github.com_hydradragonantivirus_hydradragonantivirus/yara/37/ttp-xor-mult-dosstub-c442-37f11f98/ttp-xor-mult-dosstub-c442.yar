rule TTP_XOR_MULT_DOSStub_c442 {
  strings:
    $key_c442 = { 90 2a [2] e4 32 [2] a3 30 [2] e4 21 [2] aa 2d [2] a6 27 [2] b1 2c [2] aa 62 [2] 97 }

  condition:
    any of them
}