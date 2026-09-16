rule TTP_XOR_MULT_DOSStub_d4ab {
  strings:
    $key_d4ab = { 80 c3 [2] f4 db [2] b3 d9 [2] f4 c8 [2] ba c4 [2] b6 ce [2] a1 c5 [2] ba 8b [2] 87 }

  condition:
    any of them
}