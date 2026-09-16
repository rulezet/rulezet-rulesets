rule TTP_XOR_MULT_DOSStub_d555 {
  strings:
    $key_d555 = { 81 3d [2] f5 25 [2] b2 27 [2] f5 36 [2] bb 3a [2] b7 30 [2] a0 3b [2] bb 75 [2] 86 }

  condition:
    any of them
}