rule TTP_XOR_MULT_DOSStub_d7ab {
  strings:
    $key_d7ab = { 83 c3 [2] f7 db [2] b0 d9 [2] f7 c8 [2] b9 c4 [2] b5 ce [2] a2 c5 [2] b9 8b [2] 84 }

  condition:
    any of them
}