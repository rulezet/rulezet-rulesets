rule TTP_XOR_MULT_DOSStub_b106 {
  strings:
    $key_b106 = { e5 6e [2] 91 76 [2] d6 74 [2] 91 65 [2] df 69 [2] d3 63 [2] c4 68 [2] df 26 [2] e2 }

  condition:
    any of them
}