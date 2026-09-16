rule TTP_XOR_MULT_DOSStub_9785 {
  strings:
    $key_9785 = { c3 ed [2] b7 f5 [2] f0 f7 [2] b7 e6 [2] f9 ea [2] f5 e0 [2] e2 eb [2] f9 a5 [2] c4 }

  condition:
    any of them
}