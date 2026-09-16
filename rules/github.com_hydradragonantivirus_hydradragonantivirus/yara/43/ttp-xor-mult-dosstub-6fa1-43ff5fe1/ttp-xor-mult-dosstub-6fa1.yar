rule TTP_XOR_MULT_DOSStub_6fa1 {
  strings:
    $key_6fa1 = { 3b c9 [2] 4f d1 [2] 08 d3 [2] 4f c2 [2] 01 ce [2] 0d c4 [2] 1a cf [2] 01 81 [2] 3c }

  condition:
    any of them
}