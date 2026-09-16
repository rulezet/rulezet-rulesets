rule TTP_XOR_MULT_DOSStub_1fa0 {
  strings:
    $key_1fa0 = { 4b c8 [2] 3f d0 [2] 78 d2 [2] 3f c3 [2] 71 cf [2] 7d c5 [2] 6a ce [2] 71 80 [2] 4c }

  condition:
    any of them
}