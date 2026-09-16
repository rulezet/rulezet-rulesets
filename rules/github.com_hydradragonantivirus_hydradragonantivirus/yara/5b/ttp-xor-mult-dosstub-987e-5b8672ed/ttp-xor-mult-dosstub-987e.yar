rule TTP_XOR_MULT_DOSStub_987e {
  strings:
    $key_987e = { cc 16 [2] b8 0e [2] ff 0c [2] b8 1d [2] f6 11 [2] fa 1b [2] ed 10 [2] f6 5e [2] cb }

  condition:
    any of them
}