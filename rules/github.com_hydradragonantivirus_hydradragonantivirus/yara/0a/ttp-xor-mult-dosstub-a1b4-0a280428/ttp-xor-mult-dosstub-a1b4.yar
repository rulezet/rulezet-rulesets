rule TTP_XOR_MULT_DOSStub_a1b4 {
  strings:
    $key_a1b4 = { f5 dc [2] 81 c4 [2] c6 c6 [2] 81 d7 [2] cf db [2] c3 d1 [2] d4 da [2] cf 94 [2] f2 }

  condition:
    any of them
}