rule TTP_XOR_MULT_DOSStub_bcb1 {
  strings:
    $key_bcb1 = { e8 d9 [2] 9c c1 [2] db c3 [2] 9c d2 [2] d2 de [2] de d4 [2] c9 df [2] d2 91 [2] ef }

  condition:
    any of them
}