rule TTP_XOR_MULT_DOSStub_b42c {
  strings:
    $key_b42c = { e0 44 [2] 94 5c [2] d3 5e [2] 94 4f [2] da 43 [2] d6 49 [2] c1 42 [2] da 0c [2] e7 }

  condition:
    any of them
}