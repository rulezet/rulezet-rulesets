rule TTP_XOR_MULT_DOSStub_c756 {
  strings:
    $key_c756 = { 93 3e [2] e7 26 [2] a0 24 [2] e7 35 [2] a9 39 [2] a5 33 [2] b2 38 [2] a9 76 [2] 94 }

  condition:
    any of them
}