rule TTP_XOR_MULT_DOSStub_c1d6 {
  strings:
    $key_c1d6 = { 95 be [2] e1 a6 [2] a6 a4 [2] e1 b5 [2] af b9 [2] a3 b3 [2] b4 b8 [2] af f6 [2] 92 }

  condition:
    any of them
}