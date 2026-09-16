rule TTP_XOR_MULT_DOSStub_b5b0 {
  strings:
    $key_b5b0 = { e1 d8 [2] 95 c0 [2] d2 c2 [2] 95 d3 [2] db df [2] d7 d5 [2] c0 de [2] db 90 [2] e6 }

  condition:
    any of them
}