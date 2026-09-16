rule TTP_XOR_MULT_DOSStub_9824 {
  strings:
    $key_9824 = { cc 4c [2] b8 54 [2] ff 56 [2] b8 47 [2] f6 4b [2] fa 41 [2] ed 4a [2] f6 04 [2] cb }

  condition:
    any of them
}