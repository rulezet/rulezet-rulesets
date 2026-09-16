rule TTP_XOR_MULT_DOSStub_b1e6 {
  strings:
    $key_b1e6 = { e5 8e [2] 91 96 [2] d6 94 [2] 91 85 [2] df 89 [2] d3 83 [2] c4 88 [2] df c6 [2] e2 }

  condition:
    any of them
}