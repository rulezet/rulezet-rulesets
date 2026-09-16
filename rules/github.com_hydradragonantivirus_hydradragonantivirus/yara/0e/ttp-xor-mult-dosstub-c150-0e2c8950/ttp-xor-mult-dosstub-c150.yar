rule TTP_XOR_MULT_DOSStub_c150 {
  strings:
    $key_c150 = { 95 38 [2] e1 20 [2] a6 22 [2] e1 33 [2] af 3f [2] a3 35 [2] b4 3e [2] af 70 [2] 92 }

  condition:
    any of them
}