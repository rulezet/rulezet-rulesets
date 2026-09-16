rule TTP_XOR_MULT_DOSStub_9817 {
  strings:
    $key_9817 = { cc 7f [2] b8 67 [2] ff 65 [2] b8 74 [2] f6 78 [2] fa 72 [2] ed 79 [2] f6 37 [2] cb }

  condition:
    any of them
}