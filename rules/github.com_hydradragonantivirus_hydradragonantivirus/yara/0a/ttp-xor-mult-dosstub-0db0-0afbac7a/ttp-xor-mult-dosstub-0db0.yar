rule TTP_XOR_MULT_DOSStub_0db0 {
  strings:
    $key_0db0 = { 59 d8 [2] 2d c0 [2] 6a c2 [2] 2d d3 [2] 63 df [2] 6f d5 [2] 78 de [2] 63 90 [2] 5e }

  condition:
    any of them
}