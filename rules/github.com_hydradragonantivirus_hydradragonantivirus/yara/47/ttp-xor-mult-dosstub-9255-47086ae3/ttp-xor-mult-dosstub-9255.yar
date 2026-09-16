rule TTP_XOR_MULT_DOSStub_9255 {
  strings:
    $key_9255 = { c6 3d [2] b2 25 [2] f5 27 [2] b2 36 [2] fc 3a [2] f0 30 [2] e7 3b [2] fc 75 [2] c1 }

  condition:
    any of them
}