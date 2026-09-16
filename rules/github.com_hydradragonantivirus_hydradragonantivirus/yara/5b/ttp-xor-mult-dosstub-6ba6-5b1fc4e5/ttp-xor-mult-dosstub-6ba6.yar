rule TTP_XOR_MULT_DOSStub_6ba6 {
  strings:
    $key_6ba6 = { 3f ce [2] 4b d6 [2] 0c d4 [2] 4b c5 [2] 05 c9 [2] 09 c3 [2] 1e c8 [2] 05 86 [2] 38 }

  condition:
    any of them
}