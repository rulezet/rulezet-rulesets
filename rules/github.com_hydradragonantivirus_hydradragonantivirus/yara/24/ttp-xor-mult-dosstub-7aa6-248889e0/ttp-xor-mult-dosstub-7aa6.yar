rule TTP_XOR_MULT_DOSStub_7aa6 {
  strings:
    $key_7aa6 = { 2e ce [2] 5a d6 [2] 1d d4 [2] 5a c5 [2] 14 c9 [2] 18 c3 [2] 0f c8 [2] 14 86 [2] 29 }

  condition:
    any of them
}