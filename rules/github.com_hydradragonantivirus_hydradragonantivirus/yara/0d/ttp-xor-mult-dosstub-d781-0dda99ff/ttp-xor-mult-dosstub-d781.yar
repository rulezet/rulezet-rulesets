rule TTP_XOR_MULT_DOSStub_d781 {
  strings:
    $key_d781 = { 83 e9 [2] f7 f1 [2] b0 f3 [2] f7 e2 [2] b9 ee [2] b5 e4 [2] a2 ef [2] b9 a1 [2] 84 }

  condition:
    any of them
}