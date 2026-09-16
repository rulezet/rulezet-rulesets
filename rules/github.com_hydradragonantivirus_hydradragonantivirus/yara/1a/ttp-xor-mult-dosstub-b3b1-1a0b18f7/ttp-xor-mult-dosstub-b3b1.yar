rule TTP_XOR_MULT_DOSStub_b3b1 {
  strings:
    $key_b3b1 = { e7 d9 [2] 93 c1 [2] d4 c3 [2] 93 d2 [2] dd de [2] d1 d4 [2] c6 df [2] dd 91 [2] e0 }

  condition:
    any of them
}