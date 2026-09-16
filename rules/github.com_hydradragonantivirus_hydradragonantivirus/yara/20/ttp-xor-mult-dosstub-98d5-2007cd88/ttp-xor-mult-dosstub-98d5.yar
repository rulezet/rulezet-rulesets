rule TTP_XOR_MULT_DOSStub_98d5 {
  strings:
    $key_98d5 = { cc bd [2] b8 a5 [2] ff a7 [2] b8 b6 [2] f6 ba [2] fa b0 [2] ed bb [2] f6 f5 [2] cb }

  condition:
    any of them
}