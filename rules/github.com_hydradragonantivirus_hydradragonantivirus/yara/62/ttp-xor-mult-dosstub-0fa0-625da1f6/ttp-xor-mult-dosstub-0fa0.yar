rule TTP_XOR_MULT_DOSStub_0fa0 {
  strings:
    $key_0fa0 = { 5b c8 [2] 2f d0 [2] 68 d2 [2] 2f c3 [2] 61 cf [2] 6d c5 [2] 7a ce [2] 61 80 [2] 5c }

  condition:
    any of them
}