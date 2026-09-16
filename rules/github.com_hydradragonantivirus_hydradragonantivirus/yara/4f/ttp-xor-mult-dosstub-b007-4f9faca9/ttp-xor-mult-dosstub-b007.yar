rule TTP_XOR_MULT_DOSStub_b007 {
  strings:
    $key_b007 = { e4 6f [2] 90 77 [2] d7 75 [2] 90 64 [2] de 68 [2] d2 62 [2] c5 69 [2] de 27 [2] e3 }

  condition:
    any of them
}