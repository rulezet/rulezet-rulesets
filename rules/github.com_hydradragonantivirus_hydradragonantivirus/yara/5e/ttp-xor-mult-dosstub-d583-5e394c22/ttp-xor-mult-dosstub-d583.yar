rule TTP_XOR_MULT_DOSStub_d583 {
  strings:
    $key_d583 = { 81 eb [2] f5 f3 [2] b2 f1 [2] f5 e0 [2] bb ec [2] b7 e6 [2] a0 ed [2] bb a3 [2] 86 }

  condition:
    any of them
}