rule TTP_XOR_MULT_DOSStub_9876 {
  strings:
    $key_9876 = { cc 1e [2] b8 06 [2] ff 04 [2] b8 15 [2] f6 19 [2] fa 13 [2] ed 18 [2] f6 56 [2] cb }

  condition:
    any of them
}