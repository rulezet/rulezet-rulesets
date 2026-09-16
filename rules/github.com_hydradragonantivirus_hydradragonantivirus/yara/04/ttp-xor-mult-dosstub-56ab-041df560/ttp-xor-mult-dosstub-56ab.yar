rule TTP_XOR_MULT_DOSStub_56ab {
  strings:
    $key_56ab = { 02 c3 [2] 76 db [2] 31 d9 [2] 76 c8 [2] 38 c4 [2] 34 ce [2] 23 c5 [2] 38 8b [2] 05 }

  condition:
    any of them
}