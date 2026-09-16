rule TTP_XOR_MULT_DOSStub_9379 {
  strings:
    $key_9379 = { c7 11 [2] b3 09 [2] f4 0b [2] b3 1a [2] fd 16 [2] f1 1c [2] e6 17 [2] fd 59 [2] c0 }

  condition:
    any of them
}