rule TTP_XOR_MULT_DOSStub_98c8 {
  strings:
    $key_98c8 = { cc a0 [2] b8 b8 [2] ff ba [2] b8 ab [2] f6 a7 [2] fa ad [2] ed a6 [2] f6 e8 [2] cb }

  condition:
    any of them
}