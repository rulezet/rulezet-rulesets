rule TTP_XOR_MULT_DOSStub_c131 {
  strings:
    $key_c131 = { 95 59 [2] e1 41 [2] a6 43 [2] e1 52 [2] af 5e [2] a3 54 [2] b4 5f [2] af 11 [2] 92 }

  condition:
    any of them
}