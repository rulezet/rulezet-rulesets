rule TTP_XOR_MULT_DOSStub_2da6 {
  strings:
    $key_2da6 = { 79 ce [2] 0d d6 [2] 4a d4 [2] 0d c5 [2] 43 c9 [2] 4f c3 [2] 58 c8 [2] 43 86 [2] 7e }

  condition:
    any of them
}