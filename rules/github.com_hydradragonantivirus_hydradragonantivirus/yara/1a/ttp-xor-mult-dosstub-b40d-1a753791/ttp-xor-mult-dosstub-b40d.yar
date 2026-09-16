rule TTP_XOR_MULT_DOSStub_b40d {
  strings:
    $key_b40d = { e0 65 [2] 94 7d [2] d3 7f [2] 94 6e [2] da 62 [2] d6 68 [2] c1 63 [2] da 2d [2] e7 }

  condition:
    any of them
}