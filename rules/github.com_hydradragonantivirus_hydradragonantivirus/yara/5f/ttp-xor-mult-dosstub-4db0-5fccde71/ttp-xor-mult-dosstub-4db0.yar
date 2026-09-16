rule TTP_XOR_MULT_DOSStub_4db0 {
  strings:
    $key_4db0 = { 19 d8 [2] 6d c0 [2] 2a c2 [2] 6d d3 [2] 23 df [2] 2f d5 [2] 38 de [2] 23 90 [2] 1e }

  condition:
    any of them
}