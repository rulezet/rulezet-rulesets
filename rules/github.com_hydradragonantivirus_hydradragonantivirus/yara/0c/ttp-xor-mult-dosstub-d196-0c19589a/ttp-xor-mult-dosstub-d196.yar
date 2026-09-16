rule TTP_XOR_MULT_DOSStub_d196 {
  strings:
    $key_d196 = { 85 fe [2] f1 e6 [2] b6 e4 [2] f1 f5 [2] bf f9 [2] b3 f3 [2] a4 f8 [2] bf b6 [2] 82 }

  condition:
    any of them
}