rule TTP_XOR_MULT_DOSStub_d7b7 {
  strings:
    $key_d7b7 = { 83 df [2] f7 c7 [2] b0 c5 [2] f7 d4 [2] b9 d8 [2] b5 d2 [2] a2 d9 [2] b9 97 [2] 84 }

  condition:
    any of them
}