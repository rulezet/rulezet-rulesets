rule TTP_XOR_MULT_DOSStub_b176 {
  strings:
    $key_b176 = { e5 1e [2] 91 06 [2] d6 04 [2] 91 15 [2] df 19 [2] d3 13 [2] c4 18 [2] df 56 [2] e2 }

  condition:
    any of them
}