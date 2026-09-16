rule TTP_XOR_MULT_DOSStub_e0b1 {
  strings:
    $key_e0b1 = { b4 d9 [2] c0 c1 [2] 87 c3 [2] c0 d2 [2] 8e de [2] 82 d4 [2] 95 df [2] 8e 91 [2] b3 }

  condition:
    any of them
}