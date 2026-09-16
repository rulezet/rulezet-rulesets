rule TTP_XOR_MULT_DOSStub_b416 {
  strings:
    $key_b416 = { e0 7e [2] 94 66 [2] d3 64 [2] 94 75 [2] da 79 [2] d6 73 [2] c1 78 [2] da 36 [2] e7 }

  condition:
    any of them
}