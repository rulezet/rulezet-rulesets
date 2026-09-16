rule TTP_XOR_MULT_DOSStub_c8ab {
  strings:
    $key_c8ab = { 9c c3 [2] e8 db [2] af d9 [2] e8 c8 [2] a6 c4 [2] aa ce [2] bd c5 [2] a6 8b [2] 9b }

  condition:
    any of them
}