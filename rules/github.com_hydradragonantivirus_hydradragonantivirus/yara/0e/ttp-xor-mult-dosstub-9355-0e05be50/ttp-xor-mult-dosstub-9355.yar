rule TTP_XOR_MULT_DOSStub_9355 {
  strings:
    $key_9355 = { c7 3d [2] b3 25 [2] f4 27 [2] b3 36 [2] fd 3a [2] f1 30 [2] e6 3b [2] fd 75 [2] c0 }

  condition:
    any of them
}