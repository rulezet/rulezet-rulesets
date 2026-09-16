rule TTP_XOR_MULT_DOSStub_d185 {
  strings:
    $key_d185 = { 85 ed [2] f1 f5 [2] b6 f7 [2] f1 e6 [2] bf ea [2] b3 e0 [2] a4 eb [2] bf a5 [2] 82 }

  condition:
    any of them
}