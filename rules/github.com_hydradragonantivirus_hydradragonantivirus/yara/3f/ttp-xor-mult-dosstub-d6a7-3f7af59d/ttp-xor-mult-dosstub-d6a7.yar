rule TTP_XOR_MULT_DOSStub_d6a7 {
  strings:
    $key_d6a7 = { 82 cf [2] f6 d7 [2] b1 d5 [2] f6 c4 [2] b8 c8 [2] b4 c2 [2] a3 c9 [2] b8 87 [2] 85 }

  condition:
    any of them
}