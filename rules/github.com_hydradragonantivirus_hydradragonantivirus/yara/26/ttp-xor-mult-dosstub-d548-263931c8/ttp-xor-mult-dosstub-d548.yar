rule TTP_XOR_MULT_DOSStub_d548 {
  strings:
    $key_d548 = { 81 20 [2] f5 38 [2] b2 3a [2] f5 2b [2] bb 27 [2] b7 2d [2] a0 26 [2] bb 68 [2] 86 }

  condition:
    any of them
}