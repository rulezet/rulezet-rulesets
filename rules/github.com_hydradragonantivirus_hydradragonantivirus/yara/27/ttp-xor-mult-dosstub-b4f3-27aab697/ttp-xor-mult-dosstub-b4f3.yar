rule TTP_XOR_MULT_DOSStub_b4f3 {
  strings:
    $key_b4f3 = { e0 9b [2] 94 83 [2] d3 81 [2] 94 90 [2] da 9c [2] d6 96 [2] c1 9d [2] da d3 [2] e7 }

  condition:
    any of them
}