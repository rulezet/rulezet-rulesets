rule TTP_XOR_MULT_DOSStub_b2b6 {
  strings:
    $key_b2b6 = { e6 de [2] 92 c6 [2] d5 c4 [2] 92 d5 [2] dc d9 [2] d0 d3 [2] c7 d8 [2] dc 96 [2] e1 }

  condition:
    any of them
}