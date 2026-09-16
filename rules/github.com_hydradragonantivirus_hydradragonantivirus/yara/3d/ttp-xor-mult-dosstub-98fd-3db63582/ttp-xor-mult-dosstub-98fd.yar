rule TTP_XOR_MULT_DOSStub_98fd {
  strings:
    $key_98fd = { cc 95 [2] b8 8d [2] ff 8f [2] b8 9e [2] f6 92 [2] fa 98 [2] ed 93 [2] f6 dd [2] cb }

  condition:
    any of them
}