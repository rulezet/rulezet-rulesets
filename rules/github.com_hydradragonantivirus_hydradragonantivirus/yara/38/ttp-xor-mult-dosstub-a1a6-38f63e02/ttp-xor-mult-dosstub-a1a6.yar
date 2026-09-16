rule TTP_XOR_MULT_DOSStub_a1a6 {
  strings:
    $key_a1a6 = { f5 ce [2] 81 d6 [2] c6 d4 [2] 81 c5 [2] cf c9 [2] c3 c3 [2] d4 c8 [2] cf 86 [2] f2 }

  condition:
    any of them
}