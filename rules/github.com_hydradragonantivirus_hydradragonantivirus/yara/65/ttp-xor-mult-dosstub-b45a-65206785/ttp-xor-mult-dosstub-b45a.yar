rule TTP_XOR_MULT_DOSStub_b45a {
  strings:
    $key_b45a = { e0 32 [2] 94 2a [2] d3 28 [2] 94 39 [2] da 35 [2] d6 3f [2] c1 34 [2] da 7a [2] e7 }

  condition:
    any of them
}