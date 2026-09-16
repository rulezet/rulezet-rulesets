rule TTP_XOR_MULT_DOSStub_d387 {
  strings:
    $key_d387 = { 87 ef [2] f3 f7 [2] b4 f5 [2] f3 e4 [2] bd e8 [2] b1 e2 [2] a6 e9 [2] bd a7 [2] 80 }

  condition:
    any of them
}