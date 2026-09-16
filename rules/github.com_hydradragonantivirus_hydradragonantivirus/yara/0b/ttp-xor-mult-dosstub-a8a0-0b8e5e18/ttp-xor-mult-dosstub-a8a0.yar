rule TTP_XOR_MULT_DOSStub_a8a0 {
  strings:
    $key_a8a0 = { fc c8 [2] 88 d0 [2] cf d2 [2] 88 c3 [2] c6 cf [2] ca c5 [2] dd ce [2] c6 80 [2] fb }

  condition:
    any of them
}