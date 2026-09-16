rule TTP_XOR_MULT_DOSStub_9867 {
  strings:
    $key_9867 = { cc 0f [2] b8 17 [2] ff 15 [2] b8 04 [2] f6 08 [2] fa 02 [2] ed 09 [2] f6 47 [2] cb }

  condition:
    any of them
}