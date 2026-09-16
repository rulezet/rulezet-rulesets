rule TTP_XOR_MULT_DOSStub_42ab {
  strings:
    $key_42ab = { 16 c3 [2] 62 db [2] 25 d9 [2] 62 c8 [2] 2c c4 [2] 20 ce [2] 37 c5 [2] 2c 8b [2] 11 }

  condition:
    any of them
}