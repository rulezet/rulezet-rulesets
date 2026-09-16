rule TTP_XOR_MULT_DOSStub_4ab0 {
  strings:
    $key_4ab0 = { 1e d8 [2] 6a c0 [2] 2d c2 [2] 6a d3 [2] 24 df [2] 28 d5 [2] 3f de [2] 24 90 [2] 19 }

  condition:
    any of them
}