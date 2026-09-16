rule TTP_XOR_MULT_DOSStub_9841 {
  strings:
    $key_9841 = { cc 29 [2] b8 31 [2] ff 33 [2] b8 22 [2] f6 2e [2] fa 24 [2] ed 2f [2] f6 61 [2] cb }

  condition:
    any of them
}