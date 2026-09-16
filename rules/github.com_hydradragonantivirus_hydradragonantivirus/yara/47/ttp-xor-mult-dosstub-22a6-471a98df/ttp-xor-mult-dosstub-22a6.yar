rule TTP_XOR_MULT_DOSStub_22a6 {
  strings:
    $key_22a6 = { 76 ce [2] 02 d6 [2] 45 d4 [2] 02 c5 [2] 4c c9 [2] 40 c3 [2] 57 c8 [2] 4c 86 [2] 71 }

  condition:
    any of them
}