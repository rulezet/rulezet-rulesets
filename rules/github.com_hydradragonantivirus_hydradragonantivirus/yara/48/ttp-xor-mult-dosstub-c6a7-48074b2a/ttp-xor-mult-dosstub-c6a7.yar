rule TTP_XOR_MULT_DOSStub_c6a7 {
  strings:
    $key_c6a7 = { 92 cf [2] e6 d7 [2] a1 d5 [2] e6 c4 [2] a8 c8 [2] a4 c2 [2] b3 c9 [2] a8 87 [2] 95 }

  condition:
    any of them
}