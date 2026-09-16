rule TTP_XOR_MULT_DOSStub_c7a0 {
  strings:
    $key_c7a0 = { 93 c8 [2] e7 d0 [2] a0 d2 [2] e7 c3 [2] a9 cf [2] a5 c5 [2] b2 ce [2] a9 80 [2] 94 }

  condition:
    any of them
}