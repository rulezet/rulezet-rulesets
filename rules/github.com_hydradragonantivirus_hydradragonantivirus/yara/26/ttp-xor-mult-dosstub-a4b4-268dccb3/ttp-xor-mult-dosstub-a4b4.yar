rule TTP_XOR_MULT_DOSStub_a4b4 {
  strings:
    $key_a4b4 = { f0 dc [2] 84 c4 [2] c3 c6 [2] 84 d7 [2] ca db [2] c6 d1 [2] d1 da [2] ca 94 [2] f7 }

  condition:
    any of them
}