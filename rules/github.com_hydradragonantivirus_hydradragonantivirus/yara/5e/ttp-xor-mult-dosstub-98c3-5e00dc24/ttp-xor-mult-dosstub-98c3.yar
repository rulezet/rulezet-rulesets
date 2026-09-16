rule TTP_XOR_MULT_DOSStub_98c3 {
  strings:
    $key_98c3 = { cc ab [2] b8 b3 [2] ff b1 [2] b8 a0 [2] f6 ac [2] fa a6 [2] ed ad [2] f6 e3 [2] cb }

  condition:
    any of them
}