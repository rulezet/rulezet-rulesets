rule TTP_XOR_MULT_DOSStub_c1b4 {
  strings:
    $key_c1b4 = { 95 dc [2] e1 c4 [2] a6 c6 [2] e1 d7 [2] af db [2] a3 d1 [2] b4 da [2] af 94 [2] 92 }

  condition:
    any of them
}