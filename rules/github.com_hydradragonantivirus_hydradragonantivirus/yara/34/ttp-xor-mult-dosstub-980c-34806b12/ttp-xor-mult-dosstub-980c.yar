rule TTP_XOR_MULT_DOSStub_980c {
  strings:
    $key_980c = { cc 64 [2] b8 7c [2] ff 7e [2] b8 6f [2] f6 63 [2] fa 69 [2] ed 62 [2] f6 2c [2] cb }

  condition:
    any of them
}