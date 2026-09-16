rule TTP_XOR_MULT_DOSStub_985e {
  strings:
    $key_985e = { cc 36 [2] b8 2e [2] ff 2c [2] b8 3d [2] f6 31 [2] fa 3b [2] ed 30 [2] f6 7e [2] cb }

  condition:
    any of them
}