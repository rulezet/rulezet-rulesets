rule TTP_XOR_MULT_DOSStub_a4b0 {
  strings:
    $key_a4b0 = { f0 d8 [2] 84 c0 [2] c3 c2 [2] 84 d3 [2] ca df [2] c6 d5 [2] d1 de [2] ca 90 [2] f7 }

  condition:
    any of them
}