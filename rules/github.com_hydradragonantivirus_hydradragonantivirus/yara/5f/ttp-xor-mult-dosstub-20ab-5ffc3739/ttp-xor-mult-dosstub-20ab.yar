rule TTP_XOR_MULT_DOSStub_20ab {
  strings:
    $key_20ab = { 74 c3 [2] 00 db [2] 47 d9 [2] 00 c8 [2] 4e c4 [2] 42 ce [2] 55 c5 [2] 4e 8b [2] 73 }

  condition:
    any of them
}