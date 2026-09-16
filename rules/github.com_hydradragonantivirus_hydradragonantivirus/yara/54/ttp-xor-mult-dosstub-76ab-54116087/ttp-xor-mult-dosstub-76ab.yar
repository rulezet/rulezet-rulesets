rule TTP_XOR_MULT_DOSStub_76ab {
  strings:
    $key_76ab = { 22 c3 [2] 56 db [2] 11 d9 [2] 56 c8 [2] 18 c4 [2] 14 ce [2] 03 c5 [2] 18 8b [2] 25 }

  condition:
    any of them
}