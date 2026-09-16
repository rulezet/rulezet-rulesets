rule TTP_XOR_MULT_DOSStub_b419 {
  strings:
    $key_b419 = { e0 71 [2] 94 69 [2] d3 6b [2] 94 7a [2] da 76 [2] d6 7c [2] c1 77 [2] da 39 [2] e7 }

  condition:
    any of them
}