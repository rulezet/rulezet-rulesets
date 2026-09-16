rule TTP_XOR_MULT_DOSStub_9882 {
  strings:
    $key_9882 = { cc ea [2] b8 f2 [2] ff f0 [2] b8 e1 [2] f6 ed [2] fa e7 [2] ed ec [2] f6 a2 [2] cb }

  condition:
    any of them
}