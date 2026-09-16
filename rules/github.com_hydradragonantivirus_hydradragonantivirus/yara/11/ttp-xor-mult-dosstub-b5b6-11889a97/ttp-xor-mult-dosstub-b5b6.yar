rule TTP_XOR_MULT_DOSStub_b5b6 {
  strings:
    $key_b5b6 = { e1 de [2] 95 c6 [2] d2 c4 [2] 95 d5 [2] db d9 [2] d7 d3 [2] c0 d8 [2] db 96 [2] e6 }

  condition:
    any of them
}