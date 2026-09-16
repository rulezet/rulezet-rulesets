rule TTP_XOR_MULT_DOSStub_98e2 {
  strings:
    $key_98e2 = { cc 8a [2] b8 92 [2] ff 90 [2] b8 81 [2] f6 8d [2] fa 87 [2] ed 8c [2] f6 c2 [2] cb }

  condition:
    any of them
}