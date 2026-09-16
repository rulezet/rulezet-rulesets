rule TTP_XOR_MULT_DOSStub_b423 {
  strings:
    $key_b423 = { e0 4b [2] 94 53 [2] d3 51 [2] 94 40 [2] da 4c [2] d6 46 [2] c1 4d [2] da 03 [2] e7 }

  condition:
    any of them
}