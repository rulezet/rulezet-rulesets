rule TTP_XOR_MULT_DOSStub_d5aa {
  strings:
    $key_d5aa = { 81 c2 [2] f5 da [2] b2 d8 [2] f5 c9 [2] bb c5 [2] b7 cf [2] a0 c4 [2] bb 8a [2] 86 }

  condition:
    any of them
}