rule TTP_XOR_MULT_DOSStub_b02d {
  strings:
    $key_b02d = { e4 45 [2] 90 5d [2] d7 5f [2] 90 4e [2] de 42 [2] d2 48 [2] c5 43 [2] de 0d [2] e3 }

  condition:
    any of them
}