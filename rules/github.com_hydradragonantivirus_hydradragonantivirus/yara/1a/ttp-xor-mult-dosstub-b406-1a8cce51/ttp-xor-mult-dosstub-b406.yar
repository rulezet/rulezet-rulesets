rule TTP_XOR_MULT_DOSStub_b406 {
  strings:
    $key_b406 = { e0 6e [2] 94 76 [2] d3 74 [2] 94 65 [2] da 69 [2] d6 63 [2] c1 68 [2] da 26 [2] e7 }

  condition:
    any of them
}