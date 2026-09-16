rule TTP_XOR_MULT_DOSStub_44ab {
  strings:
    $key_44ab = { 10 c3 [2] 64 db [2] 23 d9 [2] 64 c8 [2] 2a c4 [2] 26 ce [2] 31 c5 [2] 2a 8b [2] 17 }

  condition:
    any of them
}