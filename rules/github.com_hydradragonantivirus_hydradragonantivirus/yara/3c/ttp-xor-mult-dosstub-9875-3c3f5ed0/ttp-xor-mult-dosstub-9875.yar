rule TTP_XOR_MULT_DOSStub_9875 {
  strings:
    $key_9875 = { cc 1d [2] b8 05 [2] ff 07 [2] b8 16 [2] f6 1a [2] fa 10 [2] ed 1b [2] f6 55 [2] cb }

  condition:
    any of them
}