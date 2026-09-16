rule TTP_XOR_MULT_DOSStub_9860 {
  strings:
    $key_9860 = { cc 08 [2] b8 10 [2] ff 12 [2] b8 03 [2] f6 0f [2] fa 05 [2] ed 0e [2] f6 40 [2] cb }

  condition:
    any of them
}