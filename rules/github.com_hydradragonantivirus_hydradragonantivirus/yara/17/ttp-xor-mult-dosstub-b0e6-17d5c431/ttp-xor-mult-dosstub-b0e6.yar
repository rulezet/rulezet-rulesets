rule TTP_XOR_MULT_DOSStub_b0e6 {
  strings:
    $key_b0e6 = { e4 8e [2] 90 96 [2] d7 94 [2] 90 85 [2] de 89 [2] d2 83 [2] c5 88 [2] de c6 [2] e3 }

  condition:
    any of them
}