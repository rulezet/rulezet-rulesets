rule TTP_XOR_MULT_DOSStub_c6e1 {
  strings:
    $key_c6e1 = { 92 89 [2] e6 91 [2] a1 93 [2] e6 82 [2] a8 8e [2] a4 84 [2] b3 8f [2] a8 c1 [2] 95 }

  condition:
    any of them
}