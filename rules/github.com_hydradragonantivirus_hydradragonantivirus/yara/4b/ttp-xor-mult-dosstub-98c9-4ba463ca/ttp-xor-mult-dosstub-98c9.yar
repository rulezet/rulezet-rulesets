rule TTP_XOR_MULT_DOSStub_98c9 {
  strings:
    $key_98c9 = { cc a1 [2] b8 b9 [2] ff bb [2] b8 aa [2] f6 a6 [2] fa ac [2] ed a7 [2] f6 e9 [2] cb }

  condition:
    any of them
}