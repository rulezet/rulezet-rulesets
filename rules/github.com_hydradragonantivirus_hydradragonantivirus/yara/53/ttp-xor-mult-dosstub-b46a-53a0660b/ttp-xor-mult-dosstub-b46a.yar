rule TTP_XOR_MULT_DOSStub_b46a {
  strings:
    $key_b46a = { e0 02 [2] 94 1a [2] d3 18 [2] 94 09 [2] da 05 [2] d6 0f [2] c1 04 [2] da 4a [2] e7 }

  condition:
    any of them
}