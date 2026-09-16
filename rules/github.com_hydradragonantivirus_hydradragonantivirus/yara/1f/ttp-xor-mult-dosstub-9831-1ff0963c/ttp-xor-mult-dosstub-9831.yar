rule TTP_XOR_MULT_DOSStub_9831 {
  strings:
    $key_9831 = { cc 59 [2] b8 41 [2] ff 43 [2] b8 52 [2] f6 5e [2] fa 54 [2] ed 5f [2] f6 11 [2] cb }

  condition:
    any of them
}