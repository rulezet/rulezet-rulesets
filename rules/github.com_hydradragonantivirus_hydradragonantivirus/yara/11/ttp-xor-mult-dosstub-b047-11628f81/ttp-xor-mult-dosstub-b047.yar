rule TTP_XOR_MULT_DOSStub_b047 {
  strings:
    $key_b047 = { e4 2f [2] 90 37 [2] d7 35 [2] 90 24 [2] de 28 [2] d2 22 [2] c5 29 [2] de 67 [2] e3 }

  condition:
    any of them
}