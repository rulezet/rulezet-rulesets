rule TTP_XOR_MULT_DOSStub_c136 {
  strings:
    $key_c136 = { 95 5e [2] e1 46 [2] a6 44 [2] e1 55 [2] af 59 [2] a3 53 [2] b4 58 [2] af 16 [2] 92 }

  condition:
    any of them
}