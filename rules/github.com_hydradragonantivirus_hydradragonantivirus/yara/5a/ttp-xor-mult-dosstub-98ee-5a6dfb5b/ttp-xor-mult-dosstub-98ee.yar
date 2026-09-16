rule TTP_XOR_MULT_DOSStub_98ee {
  strings:
    $key_98ee = { cc 86 [2] b8 9e [2] ff 9c [2] b8 8d [2] f6 81 [2] fa 8b [2] ed 80 [2] f6 ce [2] cb }

  condition:
    any of them
}