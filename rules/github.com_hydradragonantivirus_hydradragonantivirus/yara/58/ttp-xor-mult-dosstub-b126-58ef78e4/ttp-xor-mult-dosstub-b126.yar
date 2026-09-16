rule TTP_XOR_MULT_DOSStub_b126 {
  strings:
    $key_b126 = { e5 4e [2] 91 56 [2] d6 54 [2] 91 45 [2] df 49 [2] d3 43 [2] c4 48 [2] df 06 [2] e2 }

  condition:
    any of them
}