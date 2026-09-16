rule TTP_XOR_MULT_DOSStub_06a6 {
  strings:
    $key_06a6 = { 52 ce [2] 26 d6 [2] 61 d4 [2] 26 c5 [2] 68 c9 [2] 64 c3 [2] 73 c8 [2] 68 86 [2] 55 }

  condition:
    any of them
}