rule TTP_XOR_MULT_DOSStub_b0e7 {
  strings:
    $key_b0e7 = { e4 8f [2] 90 97 [2] d7 95 [2] 90 84 [2] de 88 [2] d2 82 [2] c5 89 [2] de c7 [2] e3 }

  condition:
    any of them
}