rule TTP_XOR_MULT_DOSStub_9658 {
  strings:
    $key_9658 = { c2 30 [2] b6 28 [2] f1 2a [2] b6 3b [2] f8 37 [2] f4 3d [2] e3 36 [2] f8 78 [2] c5 }

  condition:
    any of them
}