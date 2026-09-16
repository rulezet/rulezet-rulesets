rule TTP_XOR_MULT_DOSStub_9332 {
  strings:
    $key_9332 = { c7 5a [2] b3 42 [2] f4 40 [2] b3 51 [2] fd 5d [2] f1 57 [2] e6 5c [2] fd 12 [2] c0 }

  condition:
    any of them
}