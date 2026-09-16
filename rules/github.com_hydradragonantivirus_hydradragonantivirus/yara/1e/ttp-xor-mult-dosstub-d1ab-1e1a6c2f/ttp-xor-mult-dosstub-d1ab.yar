rule TTP_XOR_MULT_DOSStub_d1ab {
  strings:
    $key_d1ab = { 85 c3 [2] f1 db [2] b6 d9 [2] f1 c8 [2] bf c4 [2] b3 ce [2] a4 c5 [2] bf 8b [2] 82 }

  condition:
    any of them
}