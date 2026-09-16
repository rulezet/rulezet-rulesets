rule TTP_XOR_MULT_DOSStub_c642 {
  strings:
    $key_c642 = { 92 2a [2] e6 32 [2] a1 30 [2] e6 21 [2] a8 2d [2] a4 27 [2] b3 2c [2] a8 62 [2] 95 }

  condition:
    any of them
}