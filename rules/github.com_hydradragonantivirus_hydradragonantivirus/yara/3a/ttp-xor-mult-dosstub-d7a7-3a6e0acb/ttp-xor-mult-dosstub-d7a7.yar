rule TTP_XOR_MULT_DOSStub_d7a7 {
  strings:
    $key_d7a7 = { 83 cf [2] f7 d7 [2] b0 d5 [2] f7 c4 [2] b9 c8 [2] b5 c2 [2] a2 c9 [2] b9 87 [2] 84 }

  condition:
    any of them
}