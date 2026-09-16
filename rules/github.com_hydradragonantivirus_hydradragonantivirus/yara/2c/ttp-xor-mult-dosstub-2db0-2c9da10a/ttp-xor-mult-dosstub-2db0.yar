rule TTP_XOR_MULT_DOSStub_2db0 {
  strings:
    $key_2db0 = { 79 d8 [2] 0d c0 [2] 4a c2 [2] 0d d3 [2] 43 df [2] 4f d5 [2] 58 de [2] 43 90 [2] 7e }

  condition:
    any of them
}