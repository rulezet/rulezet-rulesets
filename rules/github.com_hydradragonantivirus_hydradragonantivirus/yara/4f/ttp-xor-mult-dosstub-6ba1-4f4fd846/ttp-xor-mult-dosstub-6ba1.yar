rule TTP_XOR_MULT_DOSStub_6ba1 {
  strings:
    $key_6ba1 = { 3f c9 [2] 4b d1 [2] 0c d3 [2] 4b c2 [2] 05 ce [2] 09 c4 [2] 1e cf [2] 05 81 [2] 38 }

  condition:
    any of them
}