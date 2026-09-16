rule TTP_XOR_MULT_DOSStub_61a6 {
  strings:
    $key_61a6 = { 35 ce [2] 41 d6 [2] 06 d4 [2] 41 c5 [2] 0f c9 [2] 03 c3 [2] 14 c8 [2] 0f 86 [2] 32 }

  condition:
    any of them
}