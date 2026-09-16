rule TTP_XOR_MULT_DOSStub_98f4 {
  strings:
    $key_98f4 = { cc 9c [2] b8 84 [2] ff 86 [2] b8 97 [2] f6 9b [2] fa 91 [2] ed 9a [2] f6 d4 [2] cb }

  condition:
    any of them
}