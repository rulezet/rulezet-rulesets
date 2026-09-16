rule TTP_XOR_MULT_DOSStub_e6b1 {
  strings:
    $key_e6b1 = { b2 d9 [2] c6 c1 [2] 81 c3 [2] c6 d2 [2] 88 de [2] 84 d4 [2] 93 df [2] 88 91 [2] b5 }

  condition:
    any of them
}