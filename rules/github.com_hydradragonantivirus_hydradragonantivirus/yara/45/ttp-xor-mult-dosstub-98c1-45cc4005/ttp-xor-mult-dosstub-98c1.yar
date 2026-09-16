rule TTP_XOR_MULT_DOSStub_98c1 {
  strings:
    $key_98c1 = { cc a9 [2] b8 b1 [2] ff b3 [2] b8 a2 [2] f6 ae [2] fa a4 [2] ed af [2] f6 e1 [2] cb }

  condition:
    any of them
}