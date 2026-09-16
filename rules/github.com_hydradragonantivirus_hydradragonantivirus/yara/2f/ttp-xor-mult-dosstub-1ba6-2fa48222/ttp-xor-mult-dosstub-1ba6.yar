rule TTP_XOR_MULT_DOSStub_1ba6 {
  strings:
    $key_1ba6 = { 4f ce [2] 3b d6 [2] 7c d4 [2] 3b c5 [2] 75 c9 [2] 79 c3 [2] 6e c8 [2] 75 86 [2] 48 }

  condition:
    any of them
}