rule TTP_XOR_MULT_DOSStub_9804 {
  strings:
    $key_9804 = { cc 6c [2] b8 74 [2] ff 76 [2] b8 67 [2] f6 6b [2] fa 61 [2] ed 6a [2] f6 24 [2] cb }

  condition:
    any of them
}