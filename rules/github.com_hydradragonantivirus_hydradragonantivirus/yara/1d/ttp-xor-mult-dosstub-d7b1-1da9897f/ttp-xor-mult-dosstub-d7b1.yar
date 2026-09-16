rule TTP_XOR_MULT_DOSStub_d7b1 {
  strings:
    $key_d7b1 = { 83 d9 [2] f7 c1 [2] b0 c3 [2] f7 d2 [2] b9 de [2] b5 d4 [2] a2 df [2] b9 91 [2] 84 }

  condition:
    any of them
}