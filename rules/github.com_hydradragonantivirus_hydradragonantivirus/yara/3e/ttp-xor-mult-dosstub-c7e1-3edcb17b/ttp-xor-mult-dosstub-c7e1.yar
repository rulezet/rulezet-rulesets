rule TTP_XOR_MULT_DOSStub_c7e1 {
  strings:
    $key_c7e1 = { 93 89 [2] e7 91 [2] a0 93 [2] e7 82 [2] a9 8e [2] a5 84 [2] b2 8f [2] a9 c1 [2] 94 }

  condition:
    any of them
}