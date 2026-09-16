rule TTP_XOR_MULT_DOSStub_b455 {
  strings:
    $key_b455 = { e0 3d [2] 94 25 [2] d3 27 [2] 94 36 [2] da 3a [2] d6 30 [2] c1 3b [2] da 75 [2] e7 }

  condition:
    any of them
}