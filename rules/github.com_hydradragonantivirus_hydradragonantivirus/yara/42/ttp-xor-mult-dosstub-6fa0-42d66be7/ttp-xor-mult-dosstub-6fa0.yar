rule TTP_XOR_MULT_DOSStub_6fa0 {
  strings:
    $key_6fa0 = { 3b c8 [2] 4f d0 [2] 08 d2 [2] 4f c3 [2] 01 cf [2] 0d c5 [2] 1a ce [2] 01 80 [2] 3c }

  condition:
    any of them
}