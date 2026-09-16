rule TTP_XOR_MULT_DOSStub_0aa6 {
  strings:
    $key_0aa6 = { 5e ce [2] 2a d6 [2] 6d d4 [2] 2a c5 [2] 64 c9 [2] 68 c3 [2] 7f c8 [2] 64 86 [2] 59 }

  condition:
    any of them
}