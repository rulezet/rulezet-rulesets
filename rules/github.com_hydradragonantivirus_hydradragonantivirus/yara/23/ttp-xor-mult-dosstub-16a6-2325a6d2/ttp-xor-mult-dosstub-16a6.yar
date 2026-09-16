rule TTP_XOR_MULT_DOSStub_16a6 {
  strings:
    $key_16a6 = { 42 ce [2] 36 d6 [2] 71 d4 [2] 36 c5 [2] 78 c9 [2] 74 c3 [2] 63 c8 [2] 78 86 [2] 45 }

  condition:
    any of them
}