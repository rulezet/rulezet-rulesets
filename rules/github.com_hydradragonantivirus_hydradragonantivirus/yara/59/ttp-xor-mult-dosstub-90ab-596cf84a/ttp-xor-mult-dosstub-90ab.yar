rule TTP_XOR_MULT_DOSStub_90ab {
  strings:
    $key_90ab = { c4 c3 [2] b0 db [2] f7 d9 [2] b0 c8 [2] fe c4 [2] f2 ce [2] e5 c5 [2] fe 8b [2] c3 }

  condition:
    any of them
}