rule TTP_XOR_MULT_DOSStub_b458 {
  strings:
    $key_b458 = { e0 30 [2] 94 28 [2] d3 2a [2] 94 3b [2] da 37 [2] d6 3d [2] c1 36 [2] da 78 [2] e7 }

  condition:
    any of them
}