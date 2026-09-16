rule TTP_XOR_MULT_DOSStub_9895 {
  strings:
    $key_9895 = { cc fd [2] b8 e5 [2] ff e7 [2] b8 f6 [2] f6 fa [2] fa f0 [2] ed fb [2] f6 b5 [2] cb }

  condition:
    any of them
}