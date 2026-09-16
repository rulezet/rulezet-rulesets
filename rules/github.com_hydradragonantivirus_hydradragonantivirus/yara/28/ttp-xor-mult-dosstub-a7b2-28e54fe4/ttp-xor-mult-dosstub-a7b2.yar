rule TTP_XOR_MULT_DOSStub_a7b2 {
  strings:
    $key_a7b2 = { f3 da [2] 87 c2 [2] c0 c0 [2] 87 d1 [2] c9 dd [2] c5 d7 [2] d2 dc [2] c9 92 [2] f4 }

  condition:
    any of them
}