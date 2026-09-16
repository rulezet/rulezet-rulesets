rule TTP_XOR_MULT_DOSStub_985f {
  strings:
    $key_985f = { cc 37 [2] b8 2f [2] ff 2d [2] b8 3c [2] f6 30 [2] fa 3a [2] ed 31 [2] f6 7f [2] cb }

  condition:
    any of them
}