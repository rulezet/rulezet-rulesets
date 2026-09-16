rule TTP_XOR_MULT_DOSStub_9369 {
  strings:
    $key_9369 = { c7 01 [2] b3 19 [2] f4 1b [2] b3 0a [2] fd 06 [2] f1 0c [2] e6 07 [2] fd 49 [2] c0 }

  condition:
    any of them
}