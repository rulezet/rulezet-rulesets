rule TTP_XOR_MULT_DOSStub_b436 {
  strings:
    $key_b436 = { e0 5e [2] 94 46 [2] d3 44 [2] 94 55 [2] da 59 [2] d6 53 [2] c1 58 [2] da 16 [2] e7 }

  condition:
    any of them
}