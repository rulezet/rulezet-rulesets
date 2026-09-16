rule TTP_XOR_MULT_DOSStub_08a6 {
  strings:
    $key_08a6 = { 5c ce [2] 28 d6 [2] 6f d4 [2] 28 c5 [2] 66 c9 [2] 6a c3 [2] 7d c8 [2] 66 86 [2] 5b }

  condition:
    any of them
}