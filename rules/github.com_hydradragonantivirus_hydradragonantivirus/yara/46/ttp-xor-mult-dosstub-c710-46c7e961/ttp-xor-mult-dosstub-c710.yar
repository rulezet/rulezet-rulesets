rule TTP_XOR_MULT_DOSStub_c710 {
  strings:
    $key_c710 = { 93 78 [2] e7 60 [2] a0 62 [2] e7 73 [2] a9 7f [2] a5 75 [2] b2 7e [2] a9 30 [2] 94 }

  condition:
    any of them
}