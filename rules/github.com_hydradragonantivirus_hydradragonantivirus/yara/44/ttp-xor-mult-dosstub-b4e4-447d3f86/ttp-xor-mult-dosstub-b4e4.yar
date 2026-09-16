rule TTP_XOR_MULT_DOSStub_b4e4 {
  strings:
    $key_b4e4 = { e0 8c [2] 94 94 [2] d3 96 [2] 94 87 [2] da 8b [2] d6 81 [2] c1 8a [2] da c4 [2] e7 }

  condition:
    any of them
}