rule TTP_XOR_MULT_DOSStub_b47b {
  strings:
    $key_b47b = { e0 13 [2] 94 0b [2] d3 09 [2] 94 18 [2] da 14 [2] d6 1e [2] c1 15 [2] da 5b [2] e7 }

  condition:
    any of them
}