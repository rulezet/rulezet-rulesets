rule TTP_XOR_MULT_DOSStub_b41a {
  strings:
    $key_b41a = { e0 72 [2] 94 6a [2] d3 68 [2] 94 79 [2] da 75 [2] d6 7f [2] c1 74 [2] da 3a [2] e7 }

  condition:
    any of them
}