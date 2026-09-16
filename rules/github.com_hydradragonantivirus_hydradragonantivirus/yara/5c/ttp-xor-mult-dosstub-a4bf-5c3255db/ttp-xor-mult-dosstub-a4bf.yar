rule TTP_XOR_MULT_DOSStub_a4bf {
  strings:
    $key_a4bf = { f0 d7 [2] 84 cf [2] c3 cd [2] 84 dc [2] ca d0 [2] c6 da [2] d1 d1 [2] ca 9f [2] f7 }

  condition:
    any of them
}