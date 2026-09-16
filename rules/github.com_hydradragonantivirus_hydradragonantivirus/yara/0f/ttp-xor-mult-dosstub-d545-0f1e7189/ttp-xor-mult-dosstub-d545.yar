rule TTP_XOR_MULT_DOSStub_d545 {
  strings:
    $key_d545 = { 81 2d [2] f5 35 [2] b2 37 [2] f5 26 [2] bb 2a [2] b7 20 [2] a0 2b [2] bb 65 [2] 86 }

  condition:
    any of them
}