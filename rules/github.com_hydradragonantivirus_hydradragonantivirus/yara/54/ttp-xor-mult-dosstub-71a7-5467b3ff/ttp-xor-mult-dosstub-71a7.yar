rule TTP_XOR_MULT_DOSStub_71a7 {
  strings:
    $key_71a7 = { 25 cf [2] 51 d7 [2] 16 d5 [2] 51 c4 [2] 1f c8 [2] 13 c2 [2] 04 c9 [2] 1f 87 [2] 22 }

  condition:
    any of them
}