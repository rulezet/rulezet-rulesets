rule TTP_XOR_MULT_DOSStub_55ab {
  strings:
    $key_55ab = { 01 c3 [2] 75 db [2] 32 d9 [2] 75 c8 [2] 3b c4 [2] 37 ce [2] 20 c5 [2] 3b 8b [2] 06 }

  condition:
    any of them
}