rule TTP_XOR_MULT_DOSStub_98d4 {
  strings:
    $key_98d4 = { cc bc [2] b8 a4 [2] ff a6 [2] b8 b7 [2] f6 bb [2] fa b1 [2] ed ba [2] f6 f4 [2] cb }

  condition:
    any of them
}