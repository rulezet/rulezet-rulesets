rule TTP_XOR_MULT_DOSStub_9852 {
  strings:
    $key_9852 = { cc 3a [2] b8 22 [2] ff 20 [2] b8 31 [2] f6 3d [2] fa 37 [2] ed 3c [2] f6 72 [2] cb }

  condition:
    any of them
}