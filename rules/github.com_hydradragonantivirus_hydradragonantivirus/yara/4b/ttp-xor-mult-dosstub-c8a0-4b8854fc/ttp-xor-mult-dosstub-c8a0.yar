rule TTP_XOR_MULT_DOSStub_c8a0 {
  strings:
    $key_c8a0 = { 9c c8 [2] e8 d0 [2] af d2 [2] e8 c3 [2] a6 cf [2] aa c5 [2] bd ce [2] a6 80 [2] 9b }

  condition:
    any of them
}