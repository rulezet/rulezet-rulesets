rule TTP_XOR_MULT_DOSStub_c750 {
  strings:
    $key_c750 = { 93 38 [2] e7 20 [2] a0 22 [2] e7 33 [2] a9 3f [2] a5 35 [2] b2 3e [2] a9 70 [2] 94 }

  condition:
    any of them
}