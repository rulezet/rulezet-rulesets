rule TTP_XOR_MULT_DOSStub_98e0 {
  strings:
    $key_98e0 = { cc 88 [2] b8 90 [2] ff 92 [2] b8 83 [2] f6 8f [2] fa 85 [2] ed 8e [2] f6 c0 [2] cb }

  condition:
    any of them
}