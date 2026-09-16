rule TTP_XOR_MULT_DOSStub_b431 {
  strings:
    $key_b431 = { e0 59 [2] 94 41 [2] d3 43 [2] 94 52 [2] da 5e [2] d6 54 [2] c1 5f [2] da 11 [2] e7 }

  condition:
    any of them
}