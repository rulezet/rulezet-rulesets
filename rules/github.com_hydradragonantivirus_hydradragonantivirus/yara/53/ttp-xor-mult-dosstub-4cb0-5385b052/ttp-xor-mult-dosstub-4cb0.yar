rule TTP_XOR_MULT_DOSStub_4cb0 {
  strings:
    $key_4cb0 = { 18 d8 [2] 6c c0 [2] 2b c2 [2] 6c d3 [2] 22 df [2] 2e d5 [2] 39 de [2] 22 90 [2] 1f }

  condition:
    any of them
}