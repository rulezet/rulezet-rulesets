rule TTP_XOR_MULT_DOSStub_98a0 {
  strings:
    $key_98a0 = { cc c8 [2] b8 d0 [2] ff d2 [2] b8 c3 [2] f6 cf [2] fa c5 [2] ed ce [2] f6 80 [2] cb }

  condition:
    any of them
}