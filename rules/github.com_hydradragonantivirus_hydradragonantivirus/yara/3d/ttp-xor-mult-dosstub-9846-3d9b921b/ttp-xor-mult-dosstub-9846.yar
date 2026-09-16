rule TTP_XOR_MULT_DOSStub_9846 {
  strings:
    $key_9846 = { cc 2e [2] b8 36 [2] ff 34 [2] b8 25 [2] f6 29 [2] fa 23 [2] ed 28 [2] f6 66 [2] cb }

  condition:
    any of them
}