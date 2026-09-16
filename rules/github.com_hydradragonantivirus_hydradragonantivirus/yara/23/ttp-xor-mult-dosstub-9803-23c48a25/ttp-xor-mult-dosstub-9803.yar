rule TTP_XOR_MULT_DOSStub_9803 {
  strings:
    $key_9803 = { cc 6b [2] b8 73 [2] ff 71 [2] b8 60 [2] f6 6c [2] fa 66 [2] ed 6d [2] f6 23 [2] cb }

  condition:
    any of them
}