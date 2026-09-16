rule TTP_XOR_MULT_DOSStub_13ab {
  strings:
    $key_13ab = { 47 c3 [2] 33 db [2] 74 d9 [2] 33 c8 [2] 7d c4 [2] 71 ce [2] 66 c5 [2] 7d 8b [2] 40 }

  condition:
    any of them
}