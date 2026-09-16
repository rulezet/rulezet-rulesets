rule TTP_XOR_MULT_DOSStub_b42b {
  strings:
    $key_b42b = { e0 43 [2] 94 5b [2] d3 59 [2] 94 48 [2] da 44 [2] d6 4e [2] c1 45 [2] da 0b [2] e7 }

  condition:
    any of them
}