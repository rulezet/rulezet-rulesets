rule TTP_XOR_MULT_DOSStub_b4e6 {
  strings:
    $key_b4e6 = { e0 8e [2] 94 96 [2] d3 94 [2] 94 85 [2] da 89 [2] d6 83 [2] c1 88 [2] da c6 [2] e7 }

  condition:
    any of them
}