rule TTP_XOR_MULT_DOSStub_c770 {
  strings:
    $key_c770 = { 93 18 [2] e7 00 [2] a0 02 [2] e7 13 [2] a9 1f [2] a5 15 [2] b2 1e [2] a9 50 [2] 94 }

  condition:
    any of them
}