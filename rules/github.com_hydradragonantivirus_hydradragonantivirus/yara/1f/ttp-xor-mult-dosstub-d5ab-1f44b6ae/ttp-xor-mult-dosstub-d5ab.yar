rule TTP_XOR_MULT_DOSStub_d5ab {
  strings:
    $key_d5ab = { 81 c3 [2] f5 db [2] b2 d9 [2] f5 c8 [2] bb c4 [2] b7 ce [2] a0 c5 [2] bb 8b [2] 86 }

  condition:
    any of them
}