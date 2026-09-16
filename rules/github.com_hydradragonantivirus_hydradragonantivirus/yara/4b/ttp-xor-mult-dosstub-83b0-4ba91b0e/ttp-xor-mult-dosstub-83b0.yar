rule TTP_XOR_MULT_DOSStub_83b0 {
  strings:
    $key_83b0 = { d7 d8 [2] a3 c0 [2] e4 c2 [2] a3 d3 [2] ed df [2] e1 d5 [2] f6 de [2] ed 90 [2] d0 }

  condition:
    any of them
}