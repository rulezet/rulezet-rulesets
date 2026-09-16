rule TTP_XOR_MULT_DOSStub_49b0 {
  strings:
    $key_49b0 = { 1d d8 [2] 69 c0 [2] 2e c2 [2] 69 d3 [2] 27 df [2] 2b d5 [2] 3c de [2] 27 90 [2] 1a }

  condition:
    any of them
}