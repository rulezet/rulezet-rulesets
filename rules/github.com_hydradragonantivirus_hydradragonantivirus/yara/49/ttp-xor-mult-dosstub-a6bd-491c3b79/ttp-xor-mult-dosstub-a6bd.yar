rule TTP_XOR_MULT_DOSStub_a6bd {
  strings:
    $key_a6bd = { f2 d5 [2] 86 cd [2] c1 cf [2] 86 de [2] c8 d2 [2] c4 d8 [2] d3 d3 [2] c8 9d [2] f5 }

  condition:
    any of them
}