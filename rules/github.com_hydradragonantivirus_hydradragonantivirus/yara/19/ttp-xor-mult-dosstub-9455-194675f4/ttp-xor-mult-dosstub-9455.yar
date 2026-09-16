rule TTP_XOR_MULT_DOSStub_9455 {
  strings:
    $key_9455 = { c0 3d [2] b4 25 [2] f3 27 [2] b4 36 [2] fa 3a [2] f6 30 [2] e1 3b [2] fa 75 [2] c7 }

  condition:
    any of them
}