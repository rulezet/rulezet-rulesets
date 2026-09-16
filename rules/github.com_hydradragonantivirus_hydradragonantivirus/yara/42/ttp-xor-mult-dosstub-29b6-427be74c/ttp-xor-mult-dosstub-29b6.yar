rule TTP_XOR_MULT_DOSStub_29b6 {
  strings:
    $key_29b6 = { 7d de [2] 09 c6 [2] 4e c4 [2] 09 d5 [2] 47 d9 [2] 4b d3 [2] 5c d8 [2] 47 96 [2] 7a }

  condition:
    any of them
}