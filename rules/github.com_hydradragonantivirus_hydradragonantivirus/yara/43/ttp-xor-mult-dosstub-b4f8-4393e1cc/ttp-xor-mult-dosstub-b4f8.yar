rule TTP_XOR_MULT_DOSStub_b4f8 {
  strings:
    $key_b4f8 = { e0 90 [2] 94 88 [2] d3 8a [2] 94 9b [2] da 97 [2] d6 9d [2] c1 96 [2] da d8 [2] e7 }

  condition:
    any of them
}