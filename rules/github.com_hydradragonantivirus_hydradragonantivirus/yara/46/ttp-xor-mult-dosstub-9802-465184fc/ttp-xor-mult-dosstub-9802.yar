rule TTP_XOR_MULT_DOSStub_9802 {
  strings:
    $key_9802 = { cc 6a [2] b8 72 [2] ff 70 [2] b8 61 [2] f6 6d [2] fa 67 [2] ed 6c [2] f6 22 [2] cb }

  condition:
    any of them
}