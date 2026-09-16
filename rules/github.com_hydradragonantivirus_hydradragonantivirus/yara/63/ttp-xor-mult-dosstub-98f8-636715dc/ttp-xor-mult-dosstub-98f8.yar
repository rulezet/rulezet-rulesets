rule TTP_XOR_MULT_DOSStub_98f8 {
  strings:
    $key_98f8 = { cc 90 [2] b8 88 [2] ff 8a [2] b8 9b [2] f6 97 [2] fa 9d [2] ed 96 [2] f6 d8 [2] cb }

  condition:
    any of them
}