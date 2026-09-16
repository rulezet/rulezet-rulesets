rule TTP_XOR_MULT_DOSStub_d6ac {
  strings:
    $key_d6ac = { 82 c4 [2] f6 dc [2] b1 de [2] f6 cf [2] b8 c3 [2] b4 c9 [2] a3 c2 [2] b8 8c [2] 85 }

  condition:
    any of them
}