rule TTP_XOR_MULT_DOSStub_09b6 {
  strings:
    $key_09b6 = { 5d de [2] 29 c6 [2] 6e c4 [2] 29 d5 [2] 67 d9 [2] 6b d3 [2] 7c d8 [2] 67 96 [2] 5a }

  condition:
    any of them
}