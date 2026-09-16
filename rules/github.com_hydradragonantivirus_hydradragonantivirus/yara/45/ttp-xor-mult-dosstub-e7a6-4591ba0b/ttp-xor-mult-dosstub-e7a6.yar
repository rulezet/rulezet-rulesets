rule TTP_XOR_MULT_DOSStub_e7a6 {
  strings:
    $key_e7a6 = { b3 ce [2] c7 d6 [2] 80 d4 [2] c7 c5 [2] 89 c9 [2] 85 c3 [2] 92 c8 [2] 89 86 [2] b4 }

  condition:
    any of them
}