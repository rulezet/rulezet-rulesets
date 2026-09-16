rule TTP_XOR_MULT_DOSStub_2eb0 {
  strings:
    $key_2eb0 = { 7a d8 [2] 0e c0 [2] 49 c2 [2] 0e d3 [2] 40 df [2] 4c d5 [2] 5b de [2] 40 90 [2] 7d }

  condition:
    any of them
}