rule TTP_XOR_MULT_DOSStub_d8ac {
  strings:
    $key_d8ac = { 8c c4 [2] f8 dc [2] bf de [2] f8 cf [2] b6 c3 [2] ba c9 [2] ad c2 [2] b6 8c [2] 8b }

  condition:
    any of them
}