rule TTP_XOR_MULT_DOSStub_9814 {
  strings:
    $key_9814 = { cc 7c [2] b8 64 [2] ff 66 [2] b8 77 [2] f6 7b [2] fa 71 [2] ed 7a [2] f6 34 [2] cb }

  condition:
    any of them
}