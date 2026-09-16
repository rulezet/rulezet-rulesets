rule TTP_XOR_MULT_DOSStub_51ab {
  strings:
    $key_51ab = { 05 c3 [2] 71 db [2] 36 d9 [2] 71 c8 [2] 3f c4 [2] 33 ce [2] 24 c5 [2] 3f 8b [2] 02 }

  condition:
    any of them
}