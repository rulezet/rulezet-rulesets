rule TTP_XOR_MULT_DOSStub_45ab {
  strings:
    $key_45ab = { 11 c3 [2] 65 db [2] 22 d9 [2] 65 c8 [2] 2b c4 [2] 27 ce [2] 30 c5 [2] 2b 8b [2] 16 }

  condition:
    any of them
}