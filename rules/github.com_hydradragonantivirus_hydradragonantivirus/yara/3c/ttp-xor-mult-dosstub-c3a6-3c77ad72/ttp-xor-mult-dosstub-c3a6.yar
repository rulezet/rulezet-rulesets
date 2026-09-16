rule TTP_XOR_MULT_DOSStub_c3a6 {
  strings:
    $key_c3a6 = { 97 ce [2] e3 d6 [2] a4 d4 [2] e3 c5 [2] ad c9 [2] a1 c3 [2] b6 c8 [2] ad 86 [2] 90 }

  condition:
    any of them
}