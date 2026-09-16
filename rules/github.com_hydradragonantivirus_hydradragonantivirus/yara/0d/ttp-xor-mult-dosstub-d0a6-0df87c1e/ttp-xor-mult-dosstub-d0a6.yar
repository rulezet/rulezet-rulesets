rule TTP_XOR_MULT_DOSStub_d0a6 {
  strings:
    $key_d0a6 = { 84 ce [2] f0 d6 [2] b7 d4 [2] f0 c5 [2] be c9 [2] b2 c3 [2] a5 c8 [2] be 86 [2] 83 }

  condition:
    any of them
}