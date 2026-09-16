rule TTP_XOR_MULT_DOSStub_9685 {
  strings:
    $key_9685 = { c2 ed [2] b6 f5 [2] f1 f7 [2] b6 e6 [2] f8 ea [2] f4 e0 [2] e3 eb [2] f8 a5 [2] c5 }

  condition:
    any of them
}