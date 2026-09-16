rule TTP_XOR_MULT_DOSStub_d9ac {
  strings:
    $key_d9ac = { 8d c4 [2] f9 dc [2] be de [2] f9 cf [2] b7 c3 [2] bb c9 [2] ac c2 [2] b7 8c [2] 8a }

  condition:
    any of them
}