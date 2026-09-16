rule TTP_XOR_MULT_DOSStub_b415 {
  strings:
    $key_b415 = { e0 7d [2] 94 65 [2] d3 67 [2] 94 76 [2] da 7a [2] d6 70 [2] c1 7b [2] da 35 [2] e7 }

  condition:
    any of them
}