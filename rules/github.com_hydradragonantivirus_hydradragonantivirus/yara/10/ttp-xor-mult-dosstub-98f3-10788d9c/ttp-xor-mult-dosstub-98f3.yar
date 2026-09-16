rule TTP_XOR_MULT_DOSStub_98f3 {
  strings:
    $key_98f3 = { cc 9b [2] b8 83 [2] ff 81 [2] b8 90 [2] f6 9c [2] fa 96 [2] ed 9d [2] f6 d3 [2] cb }

  condition:
    any of them
}