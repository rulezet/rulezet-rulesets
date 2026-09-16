rule TTP_XOR_MULT_DOSStub_c760 {
  strings:
    $key_c760 = { 93 08 [2] e7 10 [2] a0 12 [2] e7 03 [2] a9 0f [2] a5 05 [2] b2 0e [2] a9 40 [2] 94 }

  condition:
    any of them
}