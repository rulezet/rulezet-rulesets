rule TTP_XOR_MULT_DOSStub_9827 {
  strings:
    $key_9827 = { cc 4f [2] b8 57 [2] ff 55 [2] b8 44 [2] f6 48 [2] fa 42 [2] ed 49 [2] f6 07 [2] cb }

  condition:
    any of them
}