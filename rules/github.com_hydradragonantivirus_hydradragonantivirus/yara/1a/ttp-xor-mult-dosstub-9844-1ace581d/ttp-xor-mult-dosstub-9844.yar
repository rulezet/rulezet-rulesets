rule TTP_XOR_MULT_DOSStub_9844 {
  strings:
    $key_9844 = { cc 2c [2] b8 34 [2] ff 36 [2] b8 27 [2] f6 2b [2] fa 21 [2] ed 2a [2] f6 64 [2] cb }

  condition:
    any of them
}