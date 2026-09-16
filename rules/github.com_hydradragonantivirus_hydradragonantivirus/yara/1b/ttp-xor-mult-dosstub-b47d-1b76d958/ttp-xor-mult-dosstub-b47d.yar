rule TTP_XOR_MULT_DOSStub_b47d {
  strings:
    $key_b47d = { e0 15 [2] 94 0d [2] d3 0f [2] 94 1e [2] da 12 [2] d6 18 [2] c1 13 [2] da 5d [2] e7 }

  condition:
    any of them
}