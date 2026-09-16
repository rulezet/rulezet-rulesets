rule TTP_XOR_MULT_DOSStub_e0a1 {
  strings:
    $key_e0a1 = { b4 c9 [2] c0 d1 [2] 87 d3 [2] c0 c2 [2] 8e ce [2] 82 c4 [2] 95 cf [2] 8e 81 [2] b3 }

  condition:
    any of them
}