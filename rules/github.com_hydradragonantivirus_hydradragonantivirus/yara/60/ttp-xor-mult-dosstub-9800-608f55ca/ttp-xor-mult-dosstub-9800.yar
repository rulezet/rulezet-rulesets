rule TTP_XOR_MULT_DOSStub_9800 {
  strings:
    $key_9800 = { cc 68 [2] b8 70 [2] ff 72 [2] b8 63 [2] f6 6f [2] fa 65 [2] ed 6e [2] f6 20 [2] cb }

  condition:
    any of them
}