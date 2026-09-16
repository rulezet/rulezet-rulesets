rule TTP_XOR_MULT_DOSStub_e3a1 {
  strings:
    $key_e3a1 = { b7 c9 [2] c3 d1 [2] 84 d3 [2] c3 c2 [2] 8d ce [2] 81 c4 [2] 96 cf [2] 8d 81 [2] b0 }

  condition:
    any of them
}