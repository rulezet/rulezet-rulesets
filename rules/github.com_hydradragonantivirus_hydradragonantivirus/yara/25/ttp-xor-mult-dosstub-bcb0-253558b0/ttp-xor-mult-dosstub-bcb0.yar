rule TTP_XOR_MULT_DOSStub_bcb0 {
  strings:
    $key_bcb0 = { e8 d8 [2] 9c c0 [2] db c2 [2] 9c d3 [2] d2 df [2] de d5 [2] c9 de [2] d2 90 [2] ef }

  condition:
    any of them
}