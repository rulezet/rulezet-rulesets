rule TTP_XOR_MULT_DOSStub_a1d9 {
  strings:
    $key_a1d9 = { f5 b1 [2] 81 a9 [2] c6 ab [2] 81 ba [2] cf b6 [2] c3 bc [2] d4 b7 [2] cf f9 [2] f2 }

  condition:
    any of them
}