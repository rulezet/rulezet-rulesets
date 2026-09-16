rule TTP_XOR_MULT_DOSStub_d188 {
  strings:
    $key_d188 = { 85 e0 [2] f1 f8 [2] b6 fa [2] f1 eb [2] bf e7 [2] b3 ed [2] a4 e6 [2] bf a8 [2] 82 }

  condition:
    any of them
}