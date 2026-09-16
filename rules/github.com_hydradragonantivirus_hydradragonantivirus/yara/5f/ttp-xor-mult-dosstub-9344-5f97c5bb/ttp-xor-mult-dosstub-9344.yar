rule TTP_XOR_MULT_DOSStub_9344 {
  strings:
    $key_9344 = { c7 2c [2] b3 34 [2] f4 36 [2] b3 27 [2] fd 2b [2] f1 21 [2] e6 2a [2] fd 64 [2] c0 }

  condition:
    any of them
}