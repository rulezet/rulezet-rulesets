rule TTP_XOR_MULT_DOSStub_c741 {
  strings:
    $key_c741 = { 93 29 [2] e7 31 [2] a0 33 [2] e7 22 [2] a9 2e [2] a5 24 [2] b2 2f [2] a9 61 [2] 94 }

  condition:
    any of them
}