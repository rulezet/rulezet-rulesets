rule TTP_XOR_MULT_DOSStub_980a {
  strings:
    $key_980a = { cc 62 [2] b8 7a [2] ff 78 [2] b8 69 [2] f6 65 [2] fa 6f [2] ed 64 [2] f6 2a [2] cb }

  condition:
    any of them
}