rule TTP_XOR_MULT_DOSStub_c720 {
  strings:
    $key_c720 = { 93 48 [2] e7 50 [2] a0 52 [2] e7 43 [2] a9 4f [2] a5 45 [2] b2 4e [2] a9 00 [2] 94 }

  condition:
    any of them
}