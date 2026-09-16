rule TTP_XOR_MULT_DOSStub_c776 {
  strings:
    $key_c776 = { 93 1e [2] e7 06 [2] a0 04 [2] e7 15 [2] a9 19 [2] a5 13 [2] b2 18 [2] a9 56 [2] 94 }

  condition:
    any of them
}