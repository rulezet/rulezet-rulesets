rule TTP_XOR_MULT_DOSStub_7fa0 {
  strings:
    $key_7fa0 = { 2b c8 [2] 5f d0 [2] 18 d2 [2] 5f c3 [2] 11 cf [2] 1d c5 [2] 0a ce [2] 11 80 [2] 2c }

  condition:
    any of them
}