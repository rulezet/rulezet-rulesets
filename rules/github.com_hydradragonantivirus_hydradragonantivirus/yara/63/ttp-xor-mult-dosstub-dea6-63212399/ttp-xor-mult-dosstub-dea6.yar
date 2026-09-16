rule TTP_XOR_MULT_DOSStub_dea6 {
  strings:
    $key_dea6 = { 8a ce [2] fe d6 [2] b9 d4 [2] fe c5 [2] b0 c9 [2] bc c3 [2] ab c8 [2] b0 86 [2] 8d }

  condition:
    any of them
}