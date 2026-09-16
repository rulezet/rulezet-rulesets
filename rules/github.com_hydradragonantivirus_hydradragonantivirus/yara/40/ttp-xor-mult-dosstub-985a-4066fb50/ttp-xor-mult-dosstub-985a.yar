rule TTP_XOR_MULT_DOSStub_985a {
  strings:
    $key_985a = { cc 32 [2] b8 2a [2] ff 28 [2] b8 39 [2] f6 35 [2] fa 3f [2] ed 34 [2] f6 7a [2] cb }

  condition:
    any of them
}