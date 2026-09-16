rule TTP_XOR_MULT_DOSStub_5ebb {
  strings:
    $key_5ebb = { 0a d3 [2] 7e cb [2] 39 c9 [2] 7e d8 [2] 30 d4 [2] 3c de [2] 2b d5 [2] 30 9b [2] 0d }

  condition:
    any of them
}