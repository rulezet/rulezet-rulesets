rule TTP_XOR_MULT_DOSStub_986e {
  strings:
    $key_986e = { cc 06 [2] b8 1e [2] ff 1c [2] b8 0d [2] f6 01 [2] fa 0b [2] ed 00 [2] f6 4e [2] cb }

  condition:
    any of them
}