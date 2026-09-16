rule TTP_XOR_MULT_DOSStub_b44b {
  strings:
    $key_b44b = { e0 23 [2] 94 3b [2] d3 39 [2] 94 28 [2] da 24 [2] d6 2e [2] c1 25 [2] da 6b [2] e7 }

  condition:
    any of them
}