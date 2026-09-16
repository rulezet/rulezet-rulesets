rule TTP_XOR_MULT_DOSStub_b421 {
  strings:
    $key_b421 = { e0 49 [2] 94 51 [2] d3 53 [2] 94 42 [2] da 4e [2] d6 44 [2] c1 4f [2] da 01 [2] e7 }

  condition:
    any of them
}