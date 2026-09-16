rule TTP_XOR_MULT_DOSStub_c6a1 {
  strings:
    $key_c6a1 = { 92 c9 [2] e6 d1 [2] a1 d3 [2] e6 c2 [2] a8 ce [2] a4 c4 [2] b3 cf [2] a8 81 [2] 95 }

  condition:
    any of them
}