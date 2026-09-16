rule TTP_XOR_MULT_DOSStub_eea6 {
  strings:
    $key_eea6 = { ba ce [2] ce d6 [2] 89 d4 [2] ce c5 [2] 80 c9 [2] 8c c3 [2] 9b c8 [2] 80 86 [2] bd }

  condition:
    any of them
}