rule TTP_XOR_MULT_DOSStub_7fa1 {
  strings:
    $key_7fa1 = { 2b c9 [2] 5f d1 [2] 18 d3 [2] 5f c2 [2] 11 ce [2] 1d c4 [2] 0a cf [2] 11 81 [2] 2c }

  condition:
    any of them
}