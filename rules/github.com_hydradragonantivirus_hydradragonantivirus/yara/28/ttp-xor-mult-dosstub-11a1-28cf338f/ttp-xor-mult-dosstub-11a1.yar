rule TTP_XOR_MULT_DOSStub_11a1 {
  strings:
    $key_11a1 = { 45 c9 [2] 31 d1 [2] 76 d3 [2] 31 c2 [2] 7f ce [2] 73 c4 [2] 64 cf [2] 7f 81 [2] 42 }

  condition:
    any of them
}