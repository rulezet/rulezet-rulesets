rule TTP_XOR_MULT_DOSStub_e7a1 {
  strings:
    $key_e7a1 = { b3 c9 [2] c7 d1 [2] 80 d3 [2] c7 c2 [2] 89 ce [2] 85 c4 [2] 92 cf [2] 89 81 [2] b4 }

  condition:
    any of them
}