rule TTP_XOR_MULT_DOSStub_b141 {
  strings:
    $key_b141 = { e5 29 [2] 91 31 [2] d6 33 [2] 91 22 [2] df 2e [2] d3 24 [2] c4 2f [2] df 61 [2] e2 }

  condition:
    any of them
}