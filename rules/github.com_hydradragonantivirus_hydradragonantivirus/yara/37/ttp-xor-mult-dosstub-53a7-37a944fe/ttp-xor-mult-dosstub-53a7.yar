rule TTP_XOR_MULT_DOSStub_53a7 {
  strings:
    $key_53a7 = { 07 cf [2] 73 d7 [2] 34 d5 [2] 73 c4 [2] 3d c8 [2] 31 c2 [2] 26 c9 [2] 3d 87 [2] 00 }

  condition:
    any of them
}