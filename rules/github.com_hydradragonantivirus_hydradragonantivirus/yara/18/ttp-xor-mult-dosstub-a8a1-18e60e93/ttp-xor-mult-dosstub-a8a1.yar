rule TTP_XOR_MULT_DOSStub_a8a1 {
  strings:
    $key_a8a1 = { fc c9 [2] 88 d1 [2] cf d3 [2] 88 c2 [2] c6 ce [2] ca c4 [2] dd cf [2] c6 81 [2] fb }

  condition:
    any of them
}