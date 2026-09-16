rule TTP_XOR_MULT_DOSStub_c1b1 {
  strings:
    $key_c1b1 = { 95 d9 [2] e1 c1 [2] a6 c3 [2] e1 d2 [2] af de [2] a3 d4 [2] b4 df [2] af 91 [2] 92 }

  condition:
    any of them
}