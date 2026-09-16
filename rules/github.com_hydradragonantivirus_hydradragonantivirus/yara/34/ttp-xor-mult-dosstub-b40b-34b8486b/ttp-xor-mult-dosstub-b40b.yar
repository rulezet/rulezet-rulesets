rule TTP_XOR_MULT_DOSStub_b40b {
  strings:
    $key_b40b = { e0 63 [2] 94 7b [2] d3 79 [2] 94 68 [2] da 64 [2] d6 6e [2] c1 65 [2] da 2b [2] e7 }

  condition:
    any of them
}