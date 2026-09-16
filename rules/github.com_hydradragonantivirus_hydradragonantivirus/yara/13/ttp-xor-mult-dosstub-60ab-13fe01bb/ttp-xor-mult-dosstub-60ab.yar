rule TTP_XOR_MULT_DOSStub_60ab {
  strings:
    $key_60ab = { 34 c3 [2] 40 db [2] 07 d9 [2] 40 c8 [2] 0e c4 [2] 02 ce [2] 15 c5 [2] 0e 8b [2] 33 }

  condition:
    any of them
}