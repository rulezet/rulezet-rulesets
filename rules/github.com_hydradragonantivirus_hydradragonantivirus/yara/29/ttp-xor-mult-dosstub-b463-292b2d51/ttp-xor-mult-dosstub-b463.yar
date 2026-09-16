rule TTP_XOR_MULT_DOSStub_b463 {
  strings:
    $key_b463 = { e0 0b [2] 94 13 [2] d3 11 [2] 94 00 [2] da 0c [2] d6 06 [2] c1 0d [2] da 43 [2] e7 }

  condition:
    any of them
}