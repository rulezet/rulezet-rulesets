rule TTP_XOR_MULT_DOSStub_a1a0 {
  strings:
    $key_a1a0 = { f5 c8 [2] 81 d0 [2] c6 d2 [2] 81 c3 [2] cf cf [2] c3 c5 [2] d4 ce [2] cf 80 [2] f2 }

  condition:
    any of them
}