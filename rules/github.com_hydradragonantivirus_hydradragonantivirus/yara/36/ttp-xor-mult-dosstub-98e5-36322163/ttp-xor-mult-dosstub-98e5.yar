rule TTP_XOR_MULT_DOSStub_98e5 {
  strings:
    $key_98e5 = { cc 8d [2] b8 95 [2] ff 97 [2] b8 86 [2] f6 8a [2] fa 80 [2] ed 8b [2] f6 c5 [2] cb }

  condition:
    any of them
}