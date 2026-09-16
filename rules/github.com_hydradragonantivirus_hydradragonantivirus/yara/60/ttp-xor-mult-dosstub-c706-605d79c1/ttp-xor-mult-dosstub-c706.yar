rule TTP_XOR_MULT_DOSStub_c706 {
  strings:
    $key_c706 = { 93 6e [2] e7 76 [2] a0 74 [2] e7 65 [2] a9 69 [2] a5 63 [2] b2 68 [2] a9 26 [2] 94 }

  condition:
    any of them
}