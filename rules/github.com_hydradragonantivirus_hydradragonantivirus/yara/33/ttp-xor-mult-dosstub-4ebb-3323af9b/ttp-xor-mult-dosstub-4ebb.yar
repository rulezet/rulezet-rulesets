rule TTP_XOR_MULT_DOSStub_4ebb {
  strings:
    $key_4ebb = { 1a d3 [2] 6e cb [2] 29 c9 [2] 6e d8 [2] 20 d4 [2] 2c de [2] 3b d5 [2] 20 9b [2] 1d }

  condition:
    any of them
}