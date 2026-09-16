rule TTP_XOR_MULT_DOSStub_a6bf {
  strings:
    $key_a6bf = { f2 d7 [2] 86 cf [2] c1 cd [2] 86 dc [2] c8 d0 [2] c4 da [2] d3 d1 [2] c8 9f [2] f5 }

  condition:
    any of them
}