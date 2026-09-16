rule TTP_XOR_MULT_DOSStub_18a6 {
  strings:
    $key_18a6 = { 4c ce [2] 38 d6 [2] 7f d4 [2] 38 c5 [2] 76 c9 [2] 7a c3 [2] 6d c8 [2] 76 86 [2] 4b }

  condition:
    any of them
}