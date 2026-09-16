rule TTP_XOR_MULT_DOSStub_b429 {
  strings:
    $key_b429 = { e0 41 [2] 94 59 [2] d3 5b [2] 94 4a [2] da 46 [2] d6 4c [2] c1 47 [2] da 09 [2] e7 }

  condition:
    any of them
}