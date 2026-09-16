rule TTP_XOR_MULT_DOSStub_0ba1 {
  strings:
    $key_0ba1 = { 5f c9 [2] 2b d1 [2] 6c d3 [2] 2b c2 [2] 65 ce [2] 69 c4 [2] 7e cf [2] 65 81 [2] 58 }

  condition:
    any of them
}