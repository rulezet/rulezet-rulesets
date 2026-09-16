rule TTP_XOR_MULT_DOSStub_1cb0 {
  strings:
    $key_1cb0 = { 48 d8 [2] 3c c0 [2] 7b c2 [2] 3c d3 [2] 72 df [2] 7e d5 [2] 69 de [2] 72 90 [2] 4f }

  condition:
    any of them
}