rule TTP_XOR_MULT_DOSStub_73ab {
  strings:
    $key_73ab = { 27 c3 [2] 53 db [2] 14 d9 [2] 53 c8 [2] 1d c4 [2] 11 ce [2] 06 c5 [2] 1d 8b [2] 20 }

  condition:
    any of them
}