rule TTP_XOR_MULT_DOSStub_b4e0 {
  strings:
    $key_b4e0 = { e0 88 [2] 94 90 [2] d3 92 [2] 94 83 [2] da 8f [2] d6 85 [2] c1 8e [2] da c0 [2] e7 }

  condition:
    any of them
}