rule TTP_XOR_MULT_DOSStub_c140 {
  strings:
    $key_c140 = { 95 28 [2] e1 30 [2] a6 32 [2] e1 23 [2] af 2f [2] a3 25 [2] b4 2e [2] af 60 [2] 92 }

  condition:
    any of them
}