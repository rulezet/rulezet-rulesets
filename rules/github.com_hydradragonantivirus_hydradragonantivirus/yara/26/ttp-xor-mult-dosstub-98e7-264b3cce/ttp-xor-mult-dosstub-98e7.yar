rule TTP_XOR_MULT_DOSStub_98e7 {
  strings:
    $key_98e7 = { cc 8f [2] b8 97 [2] ff 95 [2] b8 84 [2] f6 88 [2] fa 82 [2] ed 89 [2] f6 c7 [2] cb }

  condition:
    any of them
}