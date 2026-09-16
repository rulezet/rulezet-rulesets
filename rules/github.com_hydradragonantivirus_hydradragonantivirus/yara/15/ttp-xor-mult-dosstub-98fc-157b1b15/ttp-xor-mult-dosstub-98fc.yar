rule TTP_XOR_MULT_DOSStub_98fc {
  strings:
    $key_98fc = { cc 94 [2] b8 8c [2] ff 8e [2] b8 9f [2] f6 93 [2] fa 99 [2] ed 92 [2] f6 dc [2] cb }

  condition:
    any of them
}