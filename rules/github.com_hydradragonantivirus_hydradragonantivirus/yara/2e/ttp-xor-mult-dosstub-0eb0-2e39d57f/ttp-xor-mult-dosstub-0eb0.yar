rule TTP_XOR_MULT_DOSStub_0eb0 {
  strings:
    $key_0eb0 = { 5a d8 [2] 2e c0 [2] 69 c2 [2] 2e d3 [2] 60 df [2] 6c d5 [2] 7b de [2] 60 90 [2] 5d }

  condition:
    any of them
}