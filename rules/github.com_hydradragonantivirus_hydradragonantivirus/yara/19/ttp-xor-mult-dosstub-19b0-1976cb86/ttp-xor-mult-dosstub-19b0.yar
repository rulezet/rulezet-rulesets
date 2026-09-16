rule TTP_XOR_MULT_DOSStub_19b0 {
  strings:
    $key_19b0 = { 4d d8 [2] 39 c0 [2] 7e c2 [2] 39 d3 [2] 77 df [2] 7b d5 [2] 6c de [2] 77 90 [2] 4a }

  condition:
    any of them
}