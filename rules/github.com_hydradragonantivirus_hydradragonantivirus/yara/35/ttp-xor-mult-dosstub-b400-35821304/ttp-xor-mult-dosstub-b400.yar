rule TTP_XOR_MULT_DOSStub_b400 {
  strings:
    $key_b400 = { e0 68 [2] 94 70 [2] d3 72 [2] 94 63 [2] da 6f [2] d6 65 [2] c1 6e [2] da 20 [2] e7 }

  condition:
    any of them
}