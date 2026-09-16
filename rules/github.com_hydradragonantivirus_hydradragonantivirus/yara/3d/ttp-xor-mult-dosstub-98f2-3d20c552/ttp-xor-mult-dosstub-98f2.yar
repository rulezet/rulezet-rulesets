rule TTP_XOR_MULT_DOSStub_98f2 {
  strings:
    $key_98f2 = { cc 9a [2] b8 82 [2] ff 80 [2] b8 91 [2] f6 9d [2] fa 97 [2] ed 9c [2] f6 d2 [2] cb }

  condition:
    any of them
}