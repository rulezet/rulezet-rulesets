rule TTP_XOR_MULT_DOSStub_c7a7 {
  strings:
    $key_c7a7 = { 93 cf [2] e7 d7 [2] a0 d5 [2] e7 c4 [2] a9 c8 [2] a5 c2 [2] b2 c9 [2] a9 87 [2] 94 }

  condition:
    any of them
}