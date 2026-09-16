rule TTP_XOR_MULT_DOSStub_b1f1 {
  strings:
    $key_b1f1 = { e5 99 [2] 91 81 [2] d6 83 [2] 91 92 [2] df 9e [2] d3 94 [2] c4 9f [2] df d1 [2] e2 }

  condition:
    any of them
}