rule TTP_XOR_MULT_DOSStub_b440 {
  strings:
    $key_b440 = { e0 28 [2] 94 30 [2] d3 32 [2] 94 23 [2] da 2f [2] d6 25 [2] c1 2e [2] da 60 [2] e7 }

  condition:
    any of them
}