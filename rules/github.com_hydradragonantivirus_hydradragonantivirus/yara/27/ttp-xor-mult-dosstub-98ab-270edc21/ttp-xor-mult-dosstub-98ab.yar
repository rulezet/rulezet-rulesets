rule TTP_XOR_MULT_DOSStub_98ab {
  strings:
    $key_98ab = { cc c3 [2] b8 db [2] ff d9 [2] b8 c8 [2] f6 c4 [2] fa ce [2] ed c5 [2] f6 8b [2] cb }

  condition:
    any of them
}