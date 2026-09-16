rule TTP_XOR_MULT_DOSStub_5ab0 {
  strings:
    $key_5ab0 = { 0e d8 [2] 7a c0 [2] 3d c2 [2] 7a d3 [2] 34 df [2] 38 d5 [2] 2f de [2] 34 90 [2] 09 }

  condition:
    any of them
}