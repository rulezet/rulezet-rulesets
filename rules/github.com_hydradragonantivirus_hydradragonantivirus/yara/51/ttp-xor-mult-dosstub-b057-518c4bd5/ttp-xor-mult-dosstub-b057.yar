rule TTP_XOR_MULT_DOSStub_b057 {
  strings:
    $key_b057 = { e4 3f [2] 90 27 [2] d7 25 [2] 90 34 [2] de 38 [2] d2 32 [2] c5 39 [2] de 77 [2] e3 }

  condition:
    any of them
}