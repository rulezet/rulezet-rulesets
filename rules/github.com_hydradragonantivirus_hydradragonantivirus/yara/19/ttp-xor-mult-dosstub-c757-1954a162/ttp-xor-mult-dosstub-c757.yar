rule TTP_XOR_MULT_DOSStub_c757 {
  strings:
    $key_c757 = { 93 3f [2] e7 27 [2] a0 25 [2] e7 34 [2] a9 38 [2] a5 32 [2] b2 39 [2] a9 77 [2] 94 }

  condition:
    any of them
}