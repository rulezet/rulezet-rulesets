rule TTP_XOR_MULT_DOSStub_d6a6 {
  strings:
    $key_d6a6 = { 82 ce [2] f6 d6 [2] b1 d4 [2] f6 c5 [2] b8 c9 [2] b4 c3 [2] a3 c8 [2] b8 86 [2] 85 }

  condition:
    any of them
}