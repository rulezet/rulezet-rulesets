rule TTP_XOR_MULT_DOSStub_0bab {
  strings:
    $key_0bab = { 5f c3 [2] 2b db [2] 6c d9 [2] 2b c8 [2] 65 c4 [2] 69 ce [2] 7e c5 [2] 65 8b [2] 58 }

  condition:
    any of them
}