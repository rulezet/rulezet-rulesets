rule TTP_XOR_MULT_DOSStub_984c {
  strings:
    $key_984c = { cc 24 [2] b8 3c [2] ff 3e [2] b8 2f [2] f6 23 [2] fa 29 [2] ed 22 [2] f6 6c [2] cb }

  condition:
    any of them
}