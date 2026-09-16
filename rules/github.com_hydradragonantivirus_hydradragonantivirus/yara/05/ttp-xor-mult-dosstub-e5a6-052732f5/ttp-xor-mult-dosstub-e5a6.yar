rule TTP_XOR_MULT_DOSStub_e5a6 {
  strings:
    $key_e5a6 = { b1 ce [2] c5 d6 [2] 82 d4 [2] c5 c5 [2] 8b c9 [2] 87 c3 [2] 90 c8 [2] 8b 86 [2] b6 }

  condition:
    any of them
}