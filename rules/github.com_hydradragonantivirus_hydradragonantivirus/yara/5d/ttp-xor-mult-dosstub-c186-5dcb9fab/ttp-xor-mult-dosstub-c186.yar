rule TTP_XOR_MULT_DOSStub_c186 {
  strings:
    $key_c186 = { 95 ee [2] e1 f6 [2] a6 f4 [2] e1 e5 [2] af e9 [2] a3 e3 [2] b4 e8 [2] af a6 [2] 92 }

  condition:
    any of them
}