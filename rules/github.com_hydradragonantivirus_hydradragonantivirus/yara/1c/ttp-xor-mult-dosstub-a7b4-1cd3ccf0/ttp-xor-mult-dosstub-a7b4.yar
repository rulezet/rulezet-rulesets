rule TTP_XOR_MULT_DOSStub_a7b4 {
  strings:
    $key_a7b4 = { f3 dc [2] 87 c4 [2] c0 c6 [2] 87 d7 [2] c9 db [2] c5 d1 [2] d2 da [2] c9 94 [2] f4 }

  condition:
    any of them
}