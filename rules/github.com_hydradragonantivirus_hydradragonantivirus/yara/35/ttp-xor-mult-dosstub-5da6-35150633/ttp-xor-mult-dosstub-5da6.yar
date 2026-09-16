rule TTP_XOR_MULT_DOSStub_5da6 {
  strings:
    $key_5da6 = { 09 ce [2] 7d d6 [2] 3a d4 [2] 7d c5 [2] 33 c9 [2] 3f c3 [2] 28 c8 [2] 33 86 [2] 0e }

  condition:
    any of them
}