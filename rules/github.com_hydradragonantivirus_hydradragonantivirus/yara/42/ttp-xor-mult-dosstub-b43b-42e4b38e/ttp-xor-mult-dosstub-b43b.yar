rule TTP_XOR_MULT_DOSStub_b43b {
  strings:
    $key_b43b = { e0 53 [2] 94 4b [2] d3 49 [2] 94 58 [2] da 54 [2] d6 5e [2] c1 55 [2] da 1b [2] e7 }

  condition:
    any of them
}