rule TTP_XOR_MULT_DOSStub_c7e7 {
  strings:
    $key_c7e7 = { 93 8f [2] e7 97 [2] a0 95 [2] e7 84 [2] a9 88 [2] a5 82 [2] b2 89 [2] a9 c7 [2] 94 }

  condition:
    any of them
}