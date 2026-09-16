rule TTP_XOR_MULT_DOSStub_2ca1 {
  strings:
    $key_2ca1 = { 78 c9 [2] 0c d1 [2] 4b d3 [2] 0c c2 [2] 42 ce [2] 4e c4 [2] 59 cf [2] 42 81 [2] 7f }

  condition:
    any of them
}