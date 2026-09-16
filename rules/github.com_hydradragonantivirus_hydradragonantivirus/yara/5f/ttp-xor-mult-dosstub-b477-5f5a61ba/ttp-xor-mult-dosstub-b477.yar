rule TTP_XOR_MULT_DOSStub_b477 {
  strings:
    $key_b477 = { e0 1f [2] 94 07 [2] d3 05 [2] 94 14 [2] da 18 [2] d6 12 [2] c1 19 [2] da 57 [2] e7 }

  condition:
    any of them
}