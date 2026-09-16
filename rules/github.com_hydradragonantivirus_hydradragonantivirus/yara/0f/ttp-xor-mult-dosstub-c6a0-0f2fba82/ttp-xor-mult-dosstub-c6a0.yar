rule TTP_XOR_MULT_DOSStub_c6a0 {
  strings:
    $key_c6a0 = { 92 c8 [2] e6 d0 [2] a1 d2 [2] e6 c3 [2] a8 cf [2] a4 c5 [2] b3 ce [2] a8 80 [2] 95 }

  condition:
    any of them
}