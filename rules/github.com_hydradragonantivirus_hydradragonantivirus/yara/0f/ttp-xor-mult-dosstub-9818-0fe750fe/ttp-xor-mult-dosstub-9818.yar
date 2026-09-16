rule TTP_XOR_MULT_DOSStub_9818 {
  strings:
    $key_9818 = { cc 70 [2] b8 68 [2] ff 6a [2] b8 7b [2] f6 77 [2] fa 7d [2] ed 76 [2] f6 38 [2] cb }

  condition:
    any of them
}