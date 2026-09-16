rule TTP_XOR_MULT_DOSStub_a7a6 {
  strings:
    $key_a7a6 = { f3 ce [2] 87 d6 [2] c0 d4 [2] 87 c5 [2] c9 c9 [2] c5 c3 [2] d2 c8 [2] c9 86 [2] f4 }

  condition:
    any of them
}