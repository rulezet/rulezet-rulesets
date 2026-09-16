rule TTP_XOR_MULT_DOSStub_31ab {
  strings:
    $key_31ab = { 65 c3 [2] 11 db [2] 56 d9 [2] 11 c8 [2] 5f c4 [2] 53 ce [2] 44 c5 [2] 5f 8b [2] 62 }

  condition:
    any of them
}