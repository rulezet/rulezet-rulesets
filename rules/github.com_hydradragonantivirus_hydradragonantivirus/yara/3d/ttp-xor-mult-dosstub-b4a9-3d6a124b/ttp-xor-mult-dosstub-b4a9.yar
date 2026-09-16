rule TTP_XOR_MULT_DOSStub_b4a9 {
  strings:
    $key_b4a9 = { e0 c1 [2] 94 d9 [2] d3 db [2] 94 ca [2] da c6 [2] d6 cc [2] c1 c7 [2] da 89 [2] e7 }

  condition:
    any of them
}