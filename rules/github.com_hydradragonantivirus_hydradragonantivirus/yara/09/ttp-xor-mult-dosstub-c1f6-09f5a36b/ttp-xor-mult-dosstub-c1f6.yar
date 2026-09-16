rule TTP_XOR_MULT_DOSStub_c1f6 {
  strings:
    $key_c1f6 = { 95 9e [2] e1 86 [2] a6 84 [2] e1 95 [2] af 99 [2] a3 93 [2] b4 98 [2] af d6 [2] 92 }

  condition:
    any of them
}