rule TTP_XOR_MULT_DOSStub_a4a6 {
  strings:
    $key_a4a6 = { f0 ce [2] 84 d6 [2] c3 d4 [2] 84 c5 [2] ca c9 [2] c6 c3 [2] d1 c8 [2] ca 86 [2] f7 }

  condition:
    any of them
}