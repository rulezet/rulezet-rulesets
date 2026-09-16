rule TTP_XOR_MULT_DOSStub_b1e2 {
  strings:
    $key_b1e2 = { e5 8a [2] 91 92 [2] d6 90 [2] 91 81 [2] df 8d [2] d3 87 [2] c4 8c [2] df c2 [2] e2 }

  condition:
    any of them
}