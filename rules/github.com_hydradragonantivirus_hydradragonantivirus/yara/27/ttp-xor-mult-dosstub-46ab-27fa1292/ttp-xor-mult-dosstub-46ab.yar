rule TTP_XOR_MULT_DOSStub_46ab {
  strings:
    $key_46ab = { 12 c3 [2] 66 db [2] 21 d9 [2] 66 c8 [2] 28 c4 [2] 24 ce [2] 33 c5 [2] 28 8b [2] 15 }

  condition:
    any of them
}