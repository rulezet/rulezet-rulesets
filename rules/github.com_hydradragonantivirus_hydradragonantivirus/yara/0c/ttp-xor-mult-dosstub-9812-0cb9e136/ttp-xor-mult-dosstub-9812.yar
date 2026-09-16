rule TTP_XOR_MULT_DOSStub_9812 {
  strings:
    $key_9812 = { cc 7a [2] b8 62 [2] ff 60 [2] b8 71 [2] f6 7d [2] fa 77 [2] ed 7c [2] f6 32 [2] cb }

  condition:
    any of them
}