rule TTP_XOR_MULT_DOSStub_e2a6 {
  strings:
    $key_e2a6 = { b6 ce [2] c2 d6 [2] 85 d4 [2] c2 c5 [2] 8c c9 [2] 80 c3 [2] 97 c8 [2] 8c 86 [2] b1 }

  condition:
    any of them
}