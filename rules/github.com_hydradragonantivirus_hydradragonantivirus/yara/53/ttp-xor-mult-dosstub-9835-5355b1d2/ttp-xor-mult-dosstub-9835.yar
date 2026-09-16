rule TTP_XOR_MULT_DOSStub_9835 {
  strings:
    $key_9835 = { cc 5d [2] b8 45 [2] ff 47 [2] b8 56 [2] f6 5a [2] fa 50 [2] ed 5b [2] f6 15 [2] cb }

  condition:
    any of them
}