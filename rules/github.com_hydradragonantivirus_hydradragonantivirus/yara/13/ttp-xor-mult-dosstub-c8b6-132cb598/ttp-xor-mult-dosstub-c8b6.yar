rule TTP_XOR_MULT_DOSStub_c8b6 {
  strings:
    $key_c8b6 = { 9c de [2] e8 c6 [2] af c4 [2] e8 d5 [2] a6 d9 [2] aa d3 [2] bd d8 [2] a6 96 [2] 9b }

  condition:
    any of them
}