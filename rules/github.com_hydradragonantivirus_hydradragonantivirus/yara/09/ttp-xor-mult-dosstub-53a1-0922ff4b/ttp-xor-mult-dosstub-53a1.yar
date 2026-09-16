rule TTP_XOR_MULT_DOSStub_53a1 {
  strings:
    $key_53a1 = { 07 c9 [2] 73 d1 [2] 34 d3 [2] 73 c2 [2] 3d ce [2] 31 c4 [2] 26 cf [2] 3d 81 [2] 00 }

  condition:
    any of them
}