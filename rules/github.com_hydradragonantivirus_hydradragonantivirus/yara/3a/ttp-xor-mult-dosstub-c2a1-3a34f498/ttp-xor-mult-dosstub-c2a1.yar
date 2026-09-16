rule TTP_XOR_MULT_DOSStub_c2a1 {
  strings:
    $key_c2a1 = { 96 c9 [2] e2 d1 [2] a5 d3 [2] e2 c2 [2] ac ce [2] a0 c4 [2] b7 cf [2] ac 81 [2] 91 }

  condition:
    any of them
}