rule TTP_XOR_MULT_DOSStub_2ca6 {
  strings:
    $key_2ca6 = { 78 ce [2] 0c d6 [2] 4b d4 [2] 0c c5 [2] 42 c9 [2] 4e c3 [2] 59 c8 [2] 42 86 [2] 7f }

  condition:
    any of them
}