rule TTP_XOR_MULT_DOSStub_4fa1 {
  strings:
    $key_4fa1 = { 1b c9 [2] 6f d1 [2] 28 d3 [2] 6f c2 [2] 21 ce [2] 2d c4 [2] 3a cf [2] 21 81 [2] 1c }

  condition:
    any of them
}