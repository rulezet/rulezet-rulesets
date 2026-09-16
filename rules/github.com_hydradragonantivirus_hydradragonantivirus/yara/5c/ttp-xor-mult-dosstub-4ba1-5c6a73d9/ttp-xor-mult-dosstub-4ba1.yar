rule TTP_XOR_MULT_DOSStub_4ba1 {
  strings:
    $key_4ba1 = { 1f c9 [2] 6b d1 [2] 2c d3 [2] 6b c2 [2] 25 ce [2] 29 c4 [2] 3e cf [2] 25 81 [2] 18 }

  condition:
    any of them
}