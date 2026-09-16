rule TTP_XOR_MULT_DOSStub_98d2 {
  strings:
    $key_98d2 = { cc ba [2] b8 a2 [2] ff a0 [2] b8 b1 [2] f6 bd [2] fa b7 [2] ed bc [2] f6 f2 [2] cb }

  condition:
    any of them
}