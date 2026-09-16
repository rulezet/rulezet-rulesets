rule TTP_XOR_MULT_DOSStub_d3a1 {
  strings:
    $key_d3a1 = { 87 c9 [2] f3 d1 [2] b4 d3 [2] f3 c2 [2] bd ce [2] b1 c4 [2] a6 cf [2] bd 81 [2] 80 }

  condition:
    any of them
}