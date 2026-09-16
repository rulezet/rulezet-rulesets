rule TTP_XOR_MULT_DOSStub_b420 {
  strings:
    $key_b420 = { e0 48 [2] 94 50 [2] d3 52 [2] 94 43 [2] da 4f [2] d6 45 [2] c1 4e [2] da 00 [2] e7 }

  condition:
    any of them
}