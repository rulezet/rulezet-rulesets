rule TTP_XOR_MULT_DOSStub_b411 {
  strings:
    $key_b411 = { e0 79 [2] 94 61 [2] d3 63 [2] 94 72 [2] da 7e [2] d6 74 [2] c1 7f [2] da 31 [2] e7 }

  condition:
    any of them
}