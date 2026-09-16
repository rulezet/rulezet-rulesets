rule TTP_XOR_MULT_DOSStub_d7c6 {
  strings:
    $key_d7c6 = { 83 ae [2] f7 b6 [2] b0 b4 [2] f7 a5 [2] b9 a9 [2] b5 a3 [2] a2 a8 [2] b9 e6 [2] 84 }

  condition:
    any of them
}