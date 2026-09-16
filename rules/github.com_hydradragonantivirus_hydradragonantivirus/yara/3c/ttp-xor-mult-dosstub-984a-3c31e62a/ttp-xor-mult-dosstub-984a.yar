rule TTP_XOR_MULT_DOSStub_984a {
  strings:
    $key_984a = { cc 22 [2] b8 3a [2] ff 38 [2] b8 29 [2] f6 25 [2] fa 2f [2] ed 24 [2] f6 6a [2] cb }

  condition:
    any of them
}