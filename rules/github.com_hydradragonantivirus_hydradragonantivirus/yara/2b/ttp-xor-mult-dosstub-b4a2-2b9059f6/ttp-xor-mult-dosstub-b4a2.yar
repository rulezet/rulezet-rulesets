rule TTP_XOR_MULT_DOSStub_b4a2 {
  strings:
    $key_b4a2 = { e0 ca [2] 94 d2 [2] d3 d0 [2] 94 c1 [2] da cd [2] d6 c7 [2] c1 cc [2] da 82 [2] e7 }

  condition:
    any of them
}