rule TTP_XOR_MULT_DOSStub_c700 {
  strings:
    $key_c700 = { 93 68 [2] e7 70 [2] a0 72 [2] e7 63 [2] a9 6f [2] a5 65 [2] b2 6e [2] a9 20 [2] 94 }

  condition:
    any of them
}