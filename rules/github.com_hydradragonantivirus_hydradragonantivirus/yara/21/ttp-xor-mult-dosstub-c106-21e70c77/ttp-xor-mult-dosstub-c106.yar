rule TTP_XOR_MULT_DOSStub_c106 {
  strings:
    $key_c106 = { 95 6e [2] e1 76 [2] a6 74 [2] e1 65 [2] af 69 [2] a3 63 [2] b4 68 [2] af 26 [2] 92 }

  condition:
    any of them
}