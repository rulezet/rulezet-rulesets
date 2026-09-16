rule TTP_XOR_MULT_DOSStub_a6b3 {
  strings:
    $key_a6b3 = { f2 db [2] 86 c3 [2] c1 c1 [2] 86 d0 [2] c8 dc [2] c4 d6 [2] d3 dd [2] c8 93 [2] f5 }

  condition:
    any of them
}