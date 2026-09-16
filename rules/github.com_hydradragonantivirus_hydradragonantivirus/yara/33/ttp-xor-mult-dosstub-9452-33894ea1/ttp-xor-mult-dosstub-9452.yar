rule TTP_XOR_MULT_DOSStub_9452 {
  strings:
    $key_9452 = { c0 3a [2] b4 22 [2] f3 20 [2] b4 31 [2] fa 3d [2] f6 37 [2] e1 3c [2] fa 72 [2] c7 }

  condition:
    any of them
}