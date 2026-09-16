rule TTP_XOR_MULT_DOSStub_e0a6 {
  strings:
    $key_e0a6 = { b4 ce [2] c0 d6 [2] 87 d4 [2] c0 c5 [2] 8e c9 [2] 82 c3 [2] 95 c8 [2] 8e 86 [2] b3 }

  condition:
    any of them
}