rule TTP_XOR_MULT_DOSStub_4bab {
  strings:
    $key_4bab = { 1f c3 [2] 6b db [2] 2c d9 [2] 6b c8 [2] 25 c4 [2] 29 ce [2] 3e c5 [2] 25 8b [2] 18 }

  condition:
    any of them
}