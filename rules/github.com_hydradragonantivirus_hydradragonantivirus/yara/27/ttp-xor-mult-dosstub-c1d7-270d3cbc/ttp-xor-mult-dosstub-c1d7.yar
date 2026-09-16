rule TTP_XOR_MULT_DOSStub_c1d7 {
  strings:
    $key_c1d7 = { 95 bf [2] e1 a7 [2] a6 a5 [2] e1 b4 [2] af b8 [2] a3 b2 [2] b4 b9 [2] af f7 [2] 92 }

  condition:
    any of them
}