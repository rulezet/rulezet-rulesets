rule TTP_XOR_MULT_DOSStub_b1fb {
  strings:
    $key_b1fb = { e5 93 [2] 91 8b [2] d6 89 [2] 91 98 [2] df 94 [2] d3 9e [2] c4 95 [2] df db [2] e2 }

  condition:
    any of them
}