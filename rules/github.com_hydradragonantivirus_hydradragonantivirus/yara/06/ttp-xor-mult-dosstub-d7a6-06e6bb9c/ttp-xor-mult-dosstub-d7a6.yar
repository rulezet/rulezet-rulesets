rule TTP_XOR_MULT_DOSStub_d7a6 {
  strings:
    $key_d7a6 = { 83 ce [2] f7 d6 [2] b0 d4 [2] f7 c5 [2] b9 c9 [2] b5 c3 [2] a2 c8 [2] b9 86 [2] 84 }

  condition:
    any of them
}