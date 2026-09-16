rule TTP_XOR_MULT_DOSStub_9871 {
  strings:
    $key_9871 = { cc 19 [2] b8 01 [2] ff 03 [2] b8 12 [2] f6 1e [2] fa 14 [2] ed 1f [2] f6 51 [2] cb }

  condition:
    any of them
}