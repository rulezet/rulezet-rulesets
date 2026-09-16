rule TTP_XOR_MULT_DOSStub_98a4 {
  strings:
    $key_98a4 = { cc cc [2] b8 d4 [2] ff d6 [2] b8 c7 [2] f6 cb [2] fa c1 [2] ed ca [2] f6 84 [2] cb }

  condition:
    any of them
}