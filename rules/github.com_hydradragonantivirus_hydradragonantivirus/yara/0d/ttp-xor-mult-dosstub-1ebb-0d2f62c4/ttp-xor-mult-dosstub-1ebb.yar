rule TTP_XOR_MULT_DOSStub_1ebb {
  strings:
    $key_1ebb = { 4a d3 [2] 3e cb [2] 79 c9 [2] 3e d8 [2] 70 d4 [2] 7c de [2] 6b d5 [2] 70 9b [2] 4d }

  condition:
    any of them
}