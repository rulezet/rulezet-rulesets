rule TTP_XOR_MULT_DOSStub_987f {
  strings:
    $key_987f = { cc 17 [2] b8 0f [2] ff 0d [2] b8 1c [2] f6 10 [2] fa 1a [2] ed 11 [2] f6 5f [2] cb }

  condition:
    any of them
}