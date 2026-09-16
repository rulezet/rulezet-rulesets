rule TTP_XOR_MULT_DOSStub_e5a1 {
  strings:
    $key_e5a1 = { b1 c9 [2] c5 d1 [2] 82 d3 [2] c5 c2 [2] 8b ce [2] 87 c4 [2] 90 cf [2] 8b 81 [2] b6 }

  condition:
    any of them
}