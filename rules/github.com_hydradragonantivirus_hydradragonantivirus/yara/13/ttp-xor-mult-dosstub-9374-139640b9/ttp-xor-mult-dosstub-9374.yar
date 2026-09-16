rule TTP_XOR_MULT_DOSStub_9374 {
  strings:
    $key_9374 = { c7 1c [2] b3 04 [2] f4 06 [2] b3 17 [2] fd 1b [2] f1 11 [2] e6 1a [2] fd 54 [2] c0 }

  condition:
    any of them
}