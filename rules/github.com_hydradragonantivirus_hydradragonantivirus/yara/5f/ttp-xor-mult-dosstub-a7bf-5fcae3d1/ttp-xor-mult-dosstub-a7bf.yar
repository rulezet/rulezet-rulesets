rule TTP_XOR_MULT_DOSStub_a7bf {
  strings:
    $key_a7bf = { f3 d7 [2] 87 cf [2] c0 cd [2] 87 dc [2] c9 d0 [2] c5 da [2] d2 d1 [2] c9 9f [2] f4 }

  condition:
    any of them
}