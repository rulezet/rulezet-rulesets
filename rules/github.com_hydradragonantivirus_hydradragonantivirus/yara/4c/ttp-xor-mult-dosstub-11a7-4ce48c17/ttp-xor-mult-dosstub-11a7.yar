rule TTP_XOR_MULT_DOSStub_11a7 {
  strings:
    $key_11a7 = { 45 cf [2] 31 d7 [2] 76 d5 [2] 31 c4 [2] 7f c8 [2] 73 c2 [2] 64 c9 [2] 7f 87 [2] 42 }

  condition:
    any of them
}