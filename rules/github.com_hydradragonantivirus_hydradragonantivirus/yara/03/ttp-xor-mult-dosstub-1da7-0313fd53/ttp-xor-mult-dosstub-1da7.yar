rule TTP_XOR_MULT_DOSStub_1da7 {
  strings:
    $key_1da7 = { 49 cf [2] 3d d7 [2] 7a d5 [2] 3d c4 [2] 73 c8 [2] 7f c2 [2] 68 c9 [2] 73 87 [2] 4e }

  condition:
    any of them
}