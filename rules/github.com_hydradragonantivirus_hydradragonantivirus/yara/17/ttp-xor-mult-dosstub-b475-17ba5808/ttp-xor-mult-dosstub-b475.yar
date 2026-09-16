rule TTP_XOR_MULT_DOSStub_b475 {
  strings:
    $key_b475 = { e0 1d [2] 94 05 [2] d3 07 [2] 94 16 [2] da 1a [2] d6 10 [2] c1 1b [2] da 55 [2] e7 }

  condition:
    any of them
}