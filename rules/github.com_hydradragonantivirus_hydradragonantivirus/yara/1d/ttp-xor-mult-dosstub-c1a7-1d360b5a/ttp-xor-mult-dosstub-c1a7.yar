rule TTP_XOR_MULT_DOSStub_c1a7 {
  strings:
    $key_c1a7 = { 95 cf [2] e1 d7 [2] a6 d5 [2] e1 c4 [2] af c8 [2] a3 c2 [2] b4 c9 [2] af 87 [2] 92 }

  condition:
    any of them
}