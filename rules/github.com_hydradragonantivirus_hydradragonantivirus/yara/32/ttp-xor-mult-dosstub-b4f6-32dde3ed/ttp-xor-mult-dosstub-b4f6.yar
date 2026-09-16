rule TTP_XOR_MULT_DOSStub_b4f6 {
  strings:
    $key_b4f6 = { e0 9e [2] 94 86 [2] d3 84 [2] 94 95 [2] da 99 [2] d6 93 [2] c1 98 [2] da d6 [2] e7 }

  condition:
    any of them
}