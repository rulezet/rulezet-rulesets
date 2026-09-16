rule TTP_XOR_MULT_DOSStub_d6b1 {
  strings:
    $key_d6b1 = { 82 d9 [2] f6 c1 [2] b1 c3 [2] f6 d2 [2] b8 de [2] b4 d4 [2] a3 df [2] b8 91 [2] 85 }

  condition:
    any of them
}