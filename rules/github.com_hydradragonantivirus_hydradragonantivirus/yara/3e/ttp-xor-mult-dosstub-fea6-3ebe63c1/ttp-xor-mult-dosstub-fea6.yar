rule TTP_XOR_MULT_DOSStub_fea6 {
  strings:
    $key_fea6 = { aa ce [2] de d6 [2] 99 d4 [2] de c5 [2] 90 c9 [2] 9c c3 [2] 8b c8 [2] 90 86 [2] ad }

  condition:
    any of them
}