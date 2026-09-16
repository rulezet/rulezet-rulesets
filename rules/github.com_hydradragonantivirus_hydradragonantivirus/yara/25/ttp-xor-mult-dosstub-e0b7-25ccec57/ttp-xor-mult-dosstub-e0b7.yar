rule TTP_XOR_MULT_DOSStub_e0b7 {
  strings:
    $key_e0b7 = { b4 df [2] c0 c7 [2] 87 c5 [2] c0 d4 [2] 8e d8 [2] 82 d2 [2] 95 d9 [2] 8e 97 [2] b3 }

  condition:
    any of them
}