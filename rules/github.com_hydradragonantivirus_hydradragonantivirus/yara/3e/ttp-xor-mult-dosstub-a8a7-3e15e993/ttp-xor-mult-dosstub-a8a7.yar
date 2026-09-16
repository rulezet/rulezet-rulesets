rule TTP_XOR_MULT_DOSStub_a8a7 {
  strings:
    $key_a8a7 = { fc cf [2] 88 d7 [2] cf d5 [2] 88 c4 [2] c6 c8 [2] ca c2 [2] dd c9 [2] c6 87 [2] fb }

  condition:
    any of them
}