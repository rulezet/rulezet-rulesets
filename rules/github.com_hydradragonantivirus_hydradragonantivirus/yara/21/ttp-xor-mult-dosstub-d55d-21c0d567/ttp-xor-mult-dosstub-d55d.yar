rule TTP_XOR_MULT_DOSStub_d55d {
  strings:
    $key_d55d = { 81 35 [2] f5 2d [2] b2 2f [2] f5 3e [2] bb 32 [2] b7 38 [2] a0 33 [2] bb 7d [2] 86 }

  condition:
    any of them
}