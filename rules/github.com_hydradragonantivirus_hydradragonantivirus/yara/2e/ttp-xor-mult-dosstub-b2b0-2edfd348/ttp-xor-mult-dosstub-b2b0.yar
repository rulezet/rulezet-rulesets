rule TTP_XOR_MULT_DOSStub_b2b0 {
  strings:
    $key_b2b0 = { e6 d8 [2] 92 c0 [2] d5 c2 [2] 92 d3 [2] dc df [2] d0 d5 [2] c7 de [2] dc 90 [2] e1 }

  condition:
    any of them
}