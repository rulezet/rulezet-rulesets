rule TTP_XOR_MULT_DOSStub_98c2 {
  strings:
    $key_98c2 = { cc aa [2] b8 b2 [2] ff b0 [2] b8 a1 [2] f6 ad [2] fa a7 [2] ed ac [2] f6 e2 [2] cb }

  condition:
    any of them
}