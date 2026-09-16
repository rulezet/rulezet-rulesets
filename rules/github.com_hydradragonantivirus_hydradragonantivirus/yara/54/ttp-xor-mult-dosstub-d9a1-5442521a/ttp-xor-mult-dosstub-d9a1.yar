rule TTP_XOR_MULT_DOSStub_d9a1 {
  strings:
    $key_d9a1 = { 8d c9 [2] f9 d1 [2] be d3 [2] f9 c2 [2] b7 ce [2] bb c4 [2] ac cf [2] b7 81 [2] 8a }

  condition:
    any of them
}