rule TTP_XOR_MULT_DOSStub_b0f0 {
  strings:
    $key_b0f0 = { e4 98 [2] 90 80 [2] d7 82 [2] 90 93 [2] de 9f [2] d2 95 [2] c5 9e [2] de d0 [2] e3 }

  condition:
    any of them
}