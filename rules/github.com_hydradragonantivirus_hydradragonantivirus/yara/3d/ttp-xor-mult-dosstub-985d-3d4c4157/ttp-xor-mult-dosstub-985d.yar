rule TTP_XOR_MULT_DOSStub_985d {
  strings:
    $key_985d = { cc 35 [2] b8 2d [2] ff 2f [2] b8 3e [2] f6 32 [2] fa 38 [2] ed 33 [2] f6 7d [2] cb }

  condition:
    any of them
}