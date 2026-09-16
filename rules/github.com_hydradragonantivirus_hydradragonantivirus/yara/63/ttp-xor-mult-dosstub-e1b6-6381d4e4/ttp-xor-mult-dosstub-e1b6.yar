rule TTP_XOR_MULT_DOSStub_e1b6 {
  strings:
    $key_e1b6 = { b5 de [2] c1 c6 [2] 86 c4 [2] c1 d5 [2] 8f d9 [2] 83 d3 [2] 94 d8 [2] 8f 96 [2] b2 }

  condition:
    any of them
}