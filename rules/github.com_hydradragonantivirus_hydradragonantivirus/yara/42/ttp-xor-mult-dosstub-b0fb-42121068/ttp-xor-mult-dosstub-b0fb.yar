rule TTP_XOR_MULT_DOSStub_b0fb {
  strings:
    $key_b0fb = { e4 93 [2] 90 8b [2] d7 89 [2] 90 98 [2] de 94 [2] d2 9e [2] c5 95 [2] de db [2] e3 }

  condition:
    any of them
}