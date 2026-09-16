rule TTP_XOR_MULT_DOSStub_0eb6 {
  strings:
    $key_0eb6 = { 5a de [2] 2e c6 [2] 69 c4 [2] 2e d5 [2] 60 d9 [2] 6c d3 [2] 7b d8 [2] 60 96 [2] 5d }

  condition:
    any of them
}