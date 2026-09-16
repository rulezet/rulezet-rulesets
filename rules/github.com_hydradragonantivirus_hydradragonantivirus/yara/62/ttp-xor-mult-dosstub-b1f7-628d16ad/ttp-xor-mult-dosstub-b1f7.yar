rule TTP_XOR_MULT_DOSStub_b1f7 {
  strings:
    $key_b1f7 = { e5 9f [2] 91 87 [2] d6 85 [2] 91 94 [2] df 98 [2] d3 92 [2] c4 99 [2] df d7 [2] e2 }

  condition:
    any of them
}