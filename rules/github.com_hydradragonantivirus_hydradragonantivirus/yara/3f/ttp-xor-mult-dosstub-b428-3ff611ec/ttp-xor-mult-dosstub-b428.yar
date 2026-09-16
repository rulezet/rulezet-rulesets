rule TTP_XOR_MULT_DOSStub_b428 {
  strings:
    $key_b428 = { e0 40 [2] 94 58 [2] d3 5a [2] 94 4b [2] da 47 [2] d6 4d [2] c1 46 [2] da 08 [2] e7 }

  condition:
    any of them
}