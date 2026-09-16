rule TTP_XOR_MULT_DOSStub_bcb7 {
  strings:
    $key_bcb7 = { e8 df [2] 9c c7 [2] db c5 [2] 9c d4 [2] d2 d8 [2] de d2 [2] c9 d9 [2] d2 97 [2] ef }

  condition:
    any of them
}