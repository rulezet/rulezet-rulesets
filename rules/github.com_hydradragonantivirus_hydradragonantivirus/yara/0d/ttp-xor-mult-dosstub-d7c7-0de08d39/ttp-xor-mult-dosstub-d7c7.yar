rule TTP_XOR_MULT_DOSStub_d7c7 {
  strings:
    $key_d7c7 = { 83 af [2] f7 b7 [2] b0 b5 [2] f7 a4 [2] b9 a8 [2] b5 a2 [2] a2 a9 [2] b9 e7 [2] 84 }

  condition:
    any of them
}