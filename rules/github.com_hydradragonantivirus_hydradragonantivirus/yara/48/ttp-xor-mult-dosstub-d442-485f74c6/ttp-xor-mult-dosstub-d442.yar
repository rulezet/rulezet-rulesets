rule TTP_XOR_MULT_DOSStub_d442 {
  strings:
    $key_d442 = { 80 2a [2] f4 32 [2] b3 30 [2] f4 21 [2] ba 2d [2] b6 27 [2] a1 2c [2] ba 62 [2] 87 }

  condition:
    any of them
}