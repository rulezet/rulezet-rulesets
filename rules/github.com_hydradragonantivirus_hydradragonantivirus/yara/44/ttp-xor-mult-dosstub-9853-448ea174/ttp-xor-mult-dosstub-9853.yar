rule TTP_XOR_MULT_DOSStub_9853 {
  strings:
    $key_9853 = { cc 3b [2] b8 23 [2] ff 21 [2] b8 30 [2] f6 3c [2] fa 36 [2] ed 3d [2] f6 73 [2] cb }

  condition:
    any of them
}