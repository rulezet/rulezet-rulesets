rule TTP_XOR_MULT_DOSStub_37a6 {
  strings:
    $key_37a6 = { 63 ce [2] 17 d6 [2] 50 d4 [2] 17 c5 [2] 59 c9 [2] 55 c3 [2] 42 c8 [2] 59 86 [2] 64 }

  condition:
    any of them
}