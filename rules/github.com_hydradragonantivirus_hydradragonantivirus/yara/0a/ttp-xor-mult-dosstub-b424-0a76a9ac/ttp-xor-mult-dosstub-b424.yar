rule TTP_XOR_MULT_DOSStub_b424 {
  strings:
    $key_b424 = { e0 4c [2] 94 54 [2] d3 56 [2] 94 47 [2] da 4b [2] d6 41 [2] c1 4a [2] da 04 [2] e7 }

  condition:
    any of them
}