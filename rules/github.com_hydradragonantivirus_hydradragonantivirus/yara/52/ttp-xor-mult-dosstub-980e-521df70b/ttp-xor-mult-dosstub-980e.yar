rule TTP_XOR_MULT_DOSStub_980e {
  strings:
    $key_980e = { cc 66 [2] b8 7e [2] ff 7c [2] b8 6d [2] f6 61 [2] fa 6b [2] ed 60 [2] f6 2e [2] cb }

  condition:
    any of them
}