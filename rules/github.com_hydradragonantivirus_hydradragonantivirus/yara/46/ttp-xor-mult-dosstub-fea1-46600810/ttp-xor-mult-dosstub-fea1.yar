rule TTP_XOR_MULT_DOSStub_fea1 {
  strings:
    $key_fea1 = { aa c9 [2] de d1 [2] 99 d3 [2] de c2 [2] 90 ce [2] 9c c4 [2] 8b cf [2] 90 81 [2] ad }

  condition:
    any of them
}