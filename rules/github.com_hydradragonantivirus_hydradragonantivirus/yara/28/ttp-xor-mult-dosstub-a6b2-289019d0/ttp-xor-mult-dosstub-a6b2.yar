rule TTP_XOR_MULT_DOSStub_a6b2 {
  strings:
    $key_a6b2 = { f2 da [2] 86 c2 [2] c1 c0 [2] 86 d1 [2] c8 dd [2] c4 d7 [2] d3 dc [2] c8 92 [2] f5 }

  condition:
    any of them
}