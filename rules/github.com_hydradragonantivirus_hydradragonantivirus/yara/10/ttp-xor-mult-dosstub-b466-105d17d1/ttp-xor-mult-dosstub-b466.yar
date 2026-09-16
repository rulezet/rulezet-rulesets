rule TTP_XOR_MULT_DOSStub_b466 {
  strings:
    $key_b466 = { e0 0e [2] 94 16 [2] d3 14 [2] 94 05 [2] da 09 [2] d6 03 [2] c1 08 [2] da 46 [2] e7 }

  condition:
    any of them
}