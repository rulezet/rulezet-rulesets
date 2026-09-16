rule TTP_XOR_MULT_DOSStub_b425 {
  strings:
    $key_b425 = { e0 4d [2] 94 55 [2] d3 57 [2] 94 46 [2] da 4a [2] d6 40 [2] c1 4b [2] da 05 [2] e7 }

  condition:
    any of them
}