rule TTP_XOR_MULT_DOSStub_b156 {
  strings:
    $key_b156 = { e5 3e [2] 91 26 [2] d6 24 [2] 91 35 [2] df 39 [2] d3 33 [2] c4 38 [2] df 76 [2] e2 }

  condition:
    any of them
}