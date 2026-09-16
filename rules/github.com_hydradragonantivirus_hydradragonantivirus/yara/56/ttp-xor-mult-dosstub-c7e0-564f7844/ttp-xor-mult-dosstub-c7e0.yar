rule TTP_XOR_MULT_DOSStub_c7e0 {
  strings:
    $key_c7e0 = { 93 88 [2] e7 90 [2] a0 92 [2] e7 83 [2] a9 8f [2] a5 85 [2] b2 8e [2] a9 c0 [2] 94 }

  condition:
    any of them
}