rule TTP_XOR_MULT_DOSStub_b1f0 {
  strings:
    $key_b1f0 = { e5 98 [2] 91 80 [2] d6 82 [2] 91 93 [2] df 9f [2] d3 95 [2] c4 9e [2] df d0 [2] e2 }

  condition:
    any of them
}