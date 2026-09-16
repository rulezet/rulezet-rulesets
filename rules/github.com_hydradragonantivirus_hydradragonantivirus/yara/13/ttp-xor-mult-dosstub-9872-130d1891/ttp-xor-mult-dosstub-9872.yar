rule TTP_XOR_MULT_DOSStub_9872 {
  strings:
    $key_9872 = { cc 1a [2] b8 02 [2] ff 00 [2] b8 11 [2] f6 1d [2] fa 17 [2] ed 1c [2] f6 52 [2] cb }

  condition:
    any of them
}