rule TTP_XOR_MULT_DOSStub_b7b6 {
  strings:
    $key_b7b6 = { e3 de [2] 97 c6 [2] d0 c4 [2] 97 d5 [2] d9 d9 [2] d5 d3 [2] c2 d8 [2] d9 96 [2] e4 }

  condition:
    any of them
}