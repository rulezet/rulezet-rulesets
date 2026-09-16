rule TTP_XOR_MULT_DOSStub_b0b7 {
  strings:
    $key_b0b7 = { e4 df [2] 90 c7 [2] d7 c5 [2] 90 d4 [2] de d8 [2] d2 d2 [2] c5 d9 [2] de 97 [2] e3 }

  condition:
    any of them
}