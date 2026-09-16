rule TTP_XOR_MULT_DOSStub_9334 {
  strings:
    $key_9334 = { c7 5c [2] b3 44 [2] f4 46 [2] b3 57 [2] fd 5b [2] f1 51 [2] e6 5a [2] fd 14 [2] c0 }

  condition:
    any of them
}