rule TTP_XOR_MULT_DOSStub_fca0 {
  strings:
    $key_fca0 = { a8 c8 [2] dc d0 [2] 9b d2 [2] dc c3 [2] 92 cf [2] 9e c5 [2] 89 ce [2] 92 80 [2] af }

  condition:
    any of them
}