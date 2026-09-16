rule TTP_XOR_MULT_DOSStub_98ed {
  strings:
    $key_98ed = { cc 85 [2] b8 9d [2] ff 9f [2] b8 8e [2] f6 82 [2] fa 88 [2] ed 83 [2] f6 cd [2] cb }

  condition:
    any of them
}