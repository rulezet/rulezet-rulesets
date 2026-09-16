rule TTP_XOR_MULT_DOSStub_b456 {
  strings:
    $key_b456 = { e0 3e [2] 94 26 [2] d3 24 [2] 94 35 [2] da 39 [2] d6 33 [2] c1 38 [2] da 76 [2] e7 }

  condition:
    any of them
}