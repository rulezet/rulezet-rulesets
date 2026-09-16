rule TTP_XOR_MULT_DOSStub_0ebb {
  strings:
    $key_0ebb = { 5a d3 [2] 2e cb [2] 69 c9 [2] 2e d8 [2] 60 d4 [2] 6c de [2] 7b d5 [2] 60 9b [2] 5d }

  condition:
    any of them
}