rule TTP_XOR_MULT_DOSStub_d7ac {
  strings:
    $key_d7ac = { 83 c4 [2] f7 dc [2] b0 de [2] f7 cf [2] b9 c3 [2] b5 c9 [2] a2 c2 [2] b9 8c [2] 84 }

  condition:
    any of them
}