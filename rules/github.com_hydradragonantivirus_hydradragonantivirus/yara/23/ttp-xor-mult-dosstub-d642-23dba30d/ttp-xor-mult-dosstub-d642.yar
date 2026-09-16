rule TTP_XOR_MULT_DOSStub_d642 {
  strings:
    $key_d642 = { 82 2a [2] f6 32 [2] b1 30 [2] f6 21 [2] b8 2d [2] b4 27 [2] a3 2c [2] b8 62 [2] 85 }

  condition:
    any of them
}