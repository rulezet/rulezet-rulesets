rule TTP_XOR_MULT_DOSStub_9811 {
  strings:
    $key_9811 = { cc 79 [2] b8 61 [2] ff 63 [2] b8 72 [2] f6 7e [2] fa 74 [2] ed 7f [2] f6 31 [2] cb }

  condition:
    any of them
}