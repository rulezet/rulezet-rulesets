rule TTP_XOR_MULT_DOSStub_9884 {
  strings:
    $key_9884 = { cc ec [2] b8 f4 [2] ff f6 [2] b8 e7 [2] f6 eb [2] fa e1 [2] ed ea [2] f6 a4 [2] cb }

  condition:
    any of them
}