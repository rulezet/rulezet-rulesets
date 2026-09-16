rule TTP_XOR_MULT_DOSStub_b4e2 {
  strings:
    $key_b4e2 = { e0 8a [2] 94 92 [2] d3 90 [2] 94 81 [2] da 8d [2] d6 87 [2] c1 8c [2] da c2 [2] e7 }

  condition:
    any of them
}