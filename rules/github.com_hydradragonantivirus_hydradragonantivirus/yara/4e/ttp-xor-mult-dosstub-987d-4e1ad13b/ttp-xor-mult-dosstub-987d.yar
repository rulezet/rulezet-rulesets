rule TTP_XOR_MULT_DOSStub_987d {
  strings:
    $key_987d = { cc 15 [2] b8 0d [2] ff 0f [2] b8 1e [2] f6 12 [2] fa 18 [2] ed 13 [2] f6 5d [2] cb }

  condition:
    any of them
}