rule TTP_XOR_MULT_DOSStub_1bab {
  strings:
    $key_1bab = { 4f c3 [2] 3b db [2] 7c d9 [2] 3b c8 [2] 75 c4 [2] 79 ce [2] 6e c5 [2] 75 8b [2] 48 }

  condition:
    any of them
}