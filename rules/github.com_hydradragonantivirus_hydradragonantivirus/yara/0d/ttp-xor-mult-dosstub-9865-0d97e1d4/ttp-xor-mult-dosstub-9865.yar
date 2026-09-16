rule TTP_XOR_MULT_DOSStub_9865 {
  strings:
    $key_9865 = { cc 0d [2] b8 15 [2] ff 17 [2] b8 06 [2] f6 0a [2] fa 00 [2] ed 0b [2] f6 45 [2] cb }

  condition:
    any of them
}