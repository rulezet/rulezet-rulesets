rule TTP_XOR_MULT_DOSStub_b47e {
  strings:
    $key_b47e = { e0 16 [2] 94 0e [2] d3 0c [2] 94 1d [2] da 11 [2] d6 1b [2] c1 10 [2] da 5e [2] e7 }

  condition:
    any of them
}