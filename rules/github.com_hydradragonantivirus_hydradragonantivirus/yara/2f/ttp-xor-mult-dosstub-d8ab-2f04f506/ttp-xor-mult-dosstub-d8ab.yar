rule TTP_XOR_MULT_DOSStub_d8ab {
  strings:
    $key_d8ab = { 8c c3 [2] f8 db [2] bf d9 [2] f8 c8 [2] b6 c4 [2] ba ce [2] ad c5 [2] b6 8b [2] 8b }

  condition:
    any of them
}