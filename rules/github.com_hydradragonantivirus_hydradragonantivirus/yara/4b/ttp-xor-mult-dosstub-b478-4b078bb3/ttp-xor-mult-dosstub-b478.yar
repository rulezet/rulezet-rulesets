rule TTP_XOR_MULT_DOSStub_b478 {
  strings:
    $key_b478 = { e0 10 [2] 94 08 [2] d3 0a [2] 94 1b [2] da 17 [2] d6 1d [2] c1 16 [2] da 58 [2] e7 }

  condition:
    any of them
}