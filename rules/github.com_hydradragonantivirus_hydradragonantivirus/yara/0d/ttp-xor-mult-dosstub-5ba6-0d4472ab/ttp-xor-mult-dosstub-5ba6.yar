rule TTP_XOR_MULT_DOSStub_5ba6 {
  strings:
    $key_5ba6 = { 0f ce [2] 7b d6 [2] 3c d4 [2] 7b c5 [2] 35 c9 [2] 39 c3 [2] 2e c8 [2] 35 86 [2] 08 }

  condition:
    any of them
}