rule TTP_XOR_MULT_DOSStub_c897 {
  strings:
    $key_c897 = { 9c ff [2] e8 e7 [2] af e5 [2] e8 f4 [2] a6 f8 [2] aa f2 [2] bd f9 [2] a6 b7 [2] 9b }

  condition:
    any of them
}