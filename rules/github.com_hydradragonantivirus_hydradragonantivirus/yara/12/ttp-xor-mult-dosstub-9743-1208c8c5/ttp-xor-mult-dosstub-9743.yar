rule TTP_XOR_MULT_DOSStub_9743 {
  strings:
    $key_9743 = { c3 2b [2] b7 33 [2] f0 31 [2] b7 20 [2] f9 2c [2] f5 26 [2] e2 2d [2] f9 63 [2] c4 }

  condition:
    any of them
}