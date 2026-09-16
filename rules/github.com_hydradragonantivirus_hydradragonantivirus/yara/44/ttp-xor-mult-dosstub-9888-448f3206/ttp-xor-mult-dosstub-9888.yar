rule TTP_XOR_MULT_DOSStub_9888 {
  strings:
    $key_9888 = { cc e0 [2] b8 f8 [2] ff fa [2] b8 eb [2] f6 e7 [2] fa ed [2] ed e6 [2] f6 a8 [2] cb }

  condition:
    any of them
}