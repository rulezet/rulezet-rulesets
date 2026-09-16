rule TTP_XOR_MULT_DOSStub_f9bb {
  strings:
    $key_f9bb = { ad d3 [2] d9 cb [2] 9e c9 [2] d9 d8 [2] 97 d4 [2] 9b de [2] 8c d5 [2] 97 9b [2] aa }

  condition:
    any of them
}