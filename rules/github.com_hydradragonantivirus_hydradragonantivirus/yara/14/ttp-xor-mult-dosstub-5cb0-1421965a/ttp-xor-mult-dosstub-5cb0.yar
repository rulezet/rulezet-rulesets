rule TTP_XOR_MULT_DOSStub_5cb0 {
  strings:
    $key_5cb0 = { 08 d8 [2] 7c c0 [2] 3b c2 [2] 7c d3 [2] 32 df [2] 3e d5 [2] 29 de [2] 32 90 [2] 0f }

  condition:
    any of them
}