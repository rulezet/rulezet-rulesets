rule TTP_XOR_MULT_DOSStub_d487 {
  strings:
    $key_d487 = { 80 ef [2] f4 f7 [2] b3 f5 [2] f4 e4 [2] ba e8 [2] b6 e2 [2] a1 e9 [2] ba a7 [2] 87 }

  condition:
    any of them
}