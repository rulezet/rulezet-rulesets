rule TTP_XOR_MULT_DOSStub_c7f0 {
  strings:
    $key_c7f0 = { 93 98 [2] e7 80 [2] a0 82 [2] e7 93 [2] a9 9f [2] a5 95 [2] b2 9e [2] a9 d0 [2] 94 }

  condition:
    any of them
}