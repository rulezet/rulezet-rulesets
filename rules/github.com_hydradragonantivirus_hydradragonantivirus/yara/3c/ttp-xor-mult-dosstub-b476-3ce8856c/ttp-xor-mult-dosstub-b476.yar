rule TTP_XOR_MULT_DOSStub_b476 {
  strings:
    $key_b476 = { e0 1e [2] 94 06 [2] d3 04 [2] 94 15 [2] da 19 [2] d6 13 [2] c1 18 [2] da 56 [2] e7 }

  condition:
    any of them
}