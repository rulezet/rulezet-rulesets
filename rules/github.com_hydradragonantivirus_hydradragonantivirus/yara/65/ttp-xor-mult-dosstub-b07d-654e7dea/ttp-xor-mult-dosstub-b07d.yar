rule TTP_XOR_MULT_DOSStub_b07d {
  strings:
    $key_b07d = { e4 15 [2] 90 0d [2] d7 0f [2] 90 1e [2] de 12 [2] d2 18 [2] c5 13 [2] de 5d [2] e3 }

  condition:
    any of them
}