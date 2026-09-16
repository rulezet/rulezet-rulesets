rule TTP_XOR_MULT_DOSStub_c8a7 {
  strings:
    $key_c8a7 = { 9c cf [2] e8 d7 [2] af d5 [2] e8 c4 [2] a6 c8 [2] aa c2 [2] bd c9 [2] a6 87 [2] 9b }

  condition:
    any of them
}