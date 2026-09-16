rule TTP_XOR_MULT_DOSStub_9348 {
  strings:
    $key_9348 = { c7 20 [2] b3 38 [2] f4 3a [2] b3 2b [2] fd 27 [2] f1 2d [2] e6 26 [2] fd 68 [2] c0 }

  condition:
    any of them
}