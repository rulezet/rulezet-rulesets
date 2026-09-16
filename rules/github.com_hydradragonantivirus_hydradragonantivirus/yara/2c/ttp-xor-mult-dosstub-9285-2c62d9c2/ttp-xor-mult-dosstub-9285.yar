rule TTP_XOR_MULT_DOSStub_9285 {
  strings:
    $key_9285 = { c6 ed [2] b2 f5 [2] f5 f7 [2] b2 e6 [2] fc ea [2] f0 e0 [2] e7 eb [2] fc a5 [2] c1 }

  condition:
    any of them
}