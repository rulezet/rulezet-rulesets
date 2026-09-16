rule TTP_XOR_MULT_DOSStub_984e {
  strings:
    $key_984e = { cc 26 [2] b8 3e [2] ff 3c [2] b8 2d [2] f6 21 [2] fa 2b [2] ed 20 [2] f6 6e [2] cb }

  condition:
    any of them
}