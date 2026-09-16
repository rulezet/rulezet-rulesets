rule TTP_XOR_MULT_DOSStub_10ab {
  strings:
    $key_10ab = { 44 c3 [2] 30 db [2] 77 d9 [2] 30 c8 [2] 7e c4 [2] 72 ce [2] 65 c5 [2] 7e 8b [2] 43 }

  condition:
    any of them
}