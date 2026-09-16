rule TTP_XOR_MULT_DOSStub_fca1 {
  strings:
    $key_fca1 = { a8 c9 [2] dc d1 [2] 9b d3 [2] dc c2 [2] 92 ce [2] 9e c4 [2] 89 cf [2] 92 81 [2] af }

  condition:
    any of them
}