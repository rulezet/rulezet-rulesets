rule TTP_XOR_MULT_DOSStub_9baa {
  strings:
    $key_9baa = { cf c2 [2] bb da [2] fc d8 [2] bb c9 [2] f5 c5 [2] f9 cf [2] ee c4 [2] f5 8a [2] c8 }

  condition:
    any of them
}