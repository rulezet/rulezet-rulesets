rule TTP_XOR_MULT_DOSStub_b4e7 {
  strings:
    $key_b4e7 = { e0 8f [2] 94 97 [2] d3 95 [2] 94 84 [2] da 88 [2] d6 82 [2] c1 89 [2] da c7 [2] e7 }

  condition:
    any of them
}