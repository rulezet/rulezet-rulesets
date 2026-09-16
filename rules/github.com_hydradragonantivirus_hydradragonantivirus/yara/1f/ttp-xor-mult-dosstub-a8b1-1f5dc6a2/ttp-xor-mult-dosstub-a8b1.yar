rule TTP_XOR_MULT_DOSStub_a8b1 {
  strings:
    $key_a8b1 = { fc d9 [2] 88 c1 [2] cf c3 [2] 88 d2 [2] c6 de [2] ca d4 [2] dd df [2] c6 91 [2] fb }

  condition:
    any of them
}