rule TTP_XOR_MULT_DOSStub_d0ac {
  strings:
    $key_d0ac = { 84 c4 [2] f0 dc [2] b7 de [2] f0 cf [2] be c3 [2] b2 c9 [2] a5 c2 [2] be 8c [2] 83 }

  condition:
    any of them
}