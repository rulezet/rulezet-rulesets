rule TTP_XOR_MULT_DOSStub_9258 {
  strings:
    $key_9258 = { c6 30 [2] b2 28 [2] f5 2a [2] b2 3b [2] fc 37 [2] f0 3d [2] e7 36 [2] fc 78 [2] c1 }

  condition:
    any of them
}