rule TTP_XOR_MULT_DOSStub_51a6 {
  strings:
    $key_51a6 = { 05 ce [2] 71 d6 [2] 36 d4 [2] 71 c5 [2] 3f c9 [2] 33 c3 [2] 24 c8 [2] 3f 86 [2] 02 }

  condition:
    any of them
}