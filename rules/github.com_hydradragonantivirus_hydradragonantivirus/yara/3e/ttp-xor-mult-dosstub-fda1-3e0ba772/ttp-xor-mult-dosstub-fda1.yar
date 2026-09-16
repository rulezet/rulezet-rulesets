rule TTP_XOR_MULT_DOSStub_fda1 {
  strings:
    $key_fda1 = { a9 c9 [2] dd d1 [2] 9a d3 [2] dd c2 [2] 93 ce [2] 9f c4 [2] 88 cf [2] 93 81 [2] ae }

  condition:
    any of them
}