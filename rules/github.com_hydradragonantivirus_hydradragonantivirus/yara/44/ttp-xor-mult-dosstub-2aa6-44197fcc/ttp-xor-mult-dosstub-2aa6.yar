rule TTP_XOR_MULT_DOSStub_2aa6 {
  strings:
    $key_2aa6 = { 7e ce [2] 0a d6 [2] 4d d4 [2] 0a c5 [2] 44 c9 [2] 48 c3 [2] 5f c8 [2] 44 86 [2] 79 }

  condition:
    any of them
}