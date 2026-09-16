rule TTP_XOR_MULT_DOSStub_c0a0 {
  strings:
    $key_c0a0 = { 94 c8 [2] e0 d0 [2] a7 d2 [2] e0 c3 [2] ae cf [2] a2 c5 [2] b5 ce [2] ae 80 [2] 93 }

  condition:
    any of them
}