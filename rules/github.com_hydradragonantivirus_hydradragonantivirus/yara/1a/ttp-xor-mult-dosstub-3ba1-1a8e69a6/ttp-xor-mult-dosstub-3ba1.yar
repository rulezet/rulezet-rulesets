rule TTP_XOR_MULT_DOSStub_3ba1 {
  strings:
    $key_3ba1 = { 6f c9 [2] 1b d1 [2] 5c d3 [2] 1b c2 [2] 55 ce [2] 59 c4 [2] 4e cf [2] 55 81 [2] 68 }

  condition:
    any of them
}