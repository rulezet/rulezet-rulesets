rule TTP_XOR_MULT_DOSStub_9368 {
  strings:
    $key_9368 = { c7 00 [2] b3 18 [2] f4 1a [2] b3 0b [2] fd 07 [2] f1 0d [2] e6 06 [2] fd 48 [2] c0 }

  condition:
    any of them
}