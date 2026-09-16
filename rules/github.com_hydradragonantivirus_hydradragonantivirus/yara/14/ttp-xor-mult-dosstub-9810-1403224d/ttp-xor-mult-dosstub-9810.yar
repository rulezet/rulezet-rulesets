rule TTP_XOR_MULT_DOSStub_9810 {
  strings:
    $key_9810 = { cc 78 [2] b8 60 [2] ff 62 [2] b8 73 [2] f6 7f [2] fa 75 [2] ed 7e [2] f6 30 [2] cb }

  condition:
    any of them
}