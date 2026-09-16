rule TTP_XOR_MULT_DOSStub_98f9 {
  strings:
    $key_98f9 = { cc 91 [2] b8 89 [2] ff 8b [2] b8 9a [2] f6 96 [2] fa 9c [2] ed 97 [2] f6 d9 [2] cb }

  condition:
    any of them
}