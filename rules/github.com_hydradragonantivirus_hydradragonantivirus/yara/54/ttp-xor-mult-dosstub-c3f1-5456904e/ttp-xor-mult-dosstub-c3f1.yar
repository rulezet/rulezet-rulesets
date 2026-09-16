rule TTP_XOR_MULT_DOSStub_c3f1 {
  strings:
    $key_c3f1 = { 97 99 [2] e3 81 [2] a4 83 [2] e3 92 [2] ad 9e [2] a1 94 [2] b6 9f [2] ad d1 [2] 90 }

  condition:
    any of them
}