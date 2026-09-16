rule TTP_XOR_MULT_DOSStub_b0a6 {
  strings:
    $key_b0a6 = { e4 ce [2] 90 d6 [2] d7 d4 [2] 90 c5 [2] de c9 [2] d2 c3 [2] c5 c8 [2] de 86 [2] e3 }

  condition:
    any of them
}