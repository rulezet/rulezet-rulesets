rule TTP_XOR_MULT_DOSStub_981a {
  strings:
    $key_981a = { cc 72 [2] b8 6a [2] ff 68 [2] b8 79 [2] f6 75 [2] fa 7f [2] ed 74 [2] f6 3a [2] cb }

  condition:
    any of them
}