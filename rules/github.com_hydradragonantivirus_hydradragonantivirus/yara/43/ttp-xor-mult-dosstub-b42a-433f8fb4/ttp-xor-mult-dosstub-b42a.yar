rule TTP_XOR_MULT_DOSStub_b42a {
  strings:
    $key_b42a = { e0 42 [2] 94 5a [2] d3 58 [2] 94 49 [2] da 45 [2] d6 4f [2] c1 44 [2] da 0a [2] e7 }

  condition:
    any of them
}