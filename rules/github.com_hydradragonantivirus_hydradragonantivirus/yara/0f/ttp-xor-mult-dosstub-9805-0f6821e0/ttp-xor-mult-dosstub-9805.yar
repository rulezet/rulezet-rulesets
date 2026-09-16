rule TTP_XOR_MULT_DOSStub_9805 {
  strings:
    $key_9805 = { cc 6d [2] b8 75 [2] ff 77 [2] b8 66 [2] f6 6a [2] fa 60 [2] ed 6b [2] f6 25 [2] cb }

  condition:
    any of them
}