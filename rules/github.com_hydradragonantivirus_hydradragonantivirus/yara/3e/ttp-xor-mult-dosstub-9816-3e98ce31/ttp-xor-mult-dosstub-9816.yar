rule TTP_XOR_MULT_DOSStub_9816 {
  strings:
    $key_9816 = { cc 7e [2] b8 66 [2] ff 64 [2] b8 75 [2] f6 79 [2] fa 73 [2] ed 78 [2] f6 36 [2] cb }

  condition:
    any of them
}