rule TTP_XOR_MULT_DOSStub_19b6 {
  strings:
    $key_19b6 = { 4d de [2] 39 c6 [2] 7e c4 [2] 39 d5 [2] 77 d9 [2] 7b d3 [2] 6c d8 [2] 77 96 [2] 4a }

  condition:
    any of them
}