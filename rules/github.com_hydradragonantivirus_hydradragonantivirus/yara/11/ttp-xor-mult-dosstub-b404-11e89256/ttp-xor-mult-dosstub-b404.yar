rule TTP_XOR_MULT_DOSStub_b404 {
  strings:
    $key_b404 = { e0 6c [2] 94 74 [2] d3 76 [2] 94 67 [2] da 6b [2] d6 61 [2] c1 6a [2] da 24 [2] e7 }

  condition:
    any of them
}