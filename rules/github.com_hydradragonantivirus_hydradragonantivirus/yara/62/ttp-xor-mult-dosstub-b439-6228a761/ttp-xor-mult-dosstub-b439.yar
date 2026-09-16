rule TTP_XOR_MULT_DOSStub_b439 {
  strings:
    $key_b439 = { e0 51 [2] 94 49 [2] d3 4b [2] 94 5a [2] da 56 [2] d6 5c [2] c1 57 [2] da 19 [2] e7 }

  condition:
    any of them
}