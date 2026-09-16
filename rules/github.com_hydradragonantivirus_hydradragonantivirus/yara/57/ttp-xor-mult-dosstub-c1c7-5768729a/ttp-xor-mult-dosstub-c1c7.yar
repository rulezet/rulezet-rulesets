rule TTP_XOR_MULT_DOSStub_c1c7 {
  strings:
    $key_c1c7 = { 95 af [2] e1 b7 [2] a6 b5 [2] e1 a4 [2] af a8 [2] a3 a2 [2] b4 a9 [2] af e7 [2] 92 }

  condition:
    any of them
}