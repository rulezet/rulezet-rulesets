rule TTP_XOR_MULT_DOSStub_a4a7 {
  strings:
    $key_a4a7 = { f0 cf [2] 84 d7 [2] c3 d5 [2] 84 c4 [2] ca c8 [2] c6 c2 [2] d1 c9 [2] ca 87 [2] f7 }

  condition:
    any of them
}