rule TTP_XOR_MULT_DOSStub_c606 {
  strings:
    $key_c606 = { 92 6e [2] e6 76 [2] a1 74 [2] e6 65 [2] a8 69 [2] a4 63 [2] b3 68 [2] a8 26 [2] 95 }

  condition:
    any of them
}