rule TTP_XOR_MULT_DOSStub_9343 {
  strings:
    $key_9343 = { c7 2b [2] b3 33 [2] f4 31 [2] b3 20 [2] fd 2c [2] f1 26 [2] e6 2d [2] fd 63 [2] c0 }

  condition:
    any of them
}