rule TTP_XOR_MULT_DOSStub_98d3 {
  strings:
    $key_98d3 = { cc bb [2] b8 a3 [2] ff a1 [2] b8 b0 [2] f6 bc [2] fa b6 [2] ed bd [2] f6 f3 [2] cb }

  condition:
    any of them
}