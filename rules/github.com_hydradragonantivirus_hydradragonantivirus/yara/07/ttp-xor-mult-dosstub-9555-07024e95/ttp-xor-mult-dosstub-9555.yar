rule TTP_XOR_MULT_DOSStub_9555 {
  strings:
    $key_9555 = { c1 3d [2] b5 25 [2] f2 27 [2] b5 36 [2] fb 3a [2] f7 30 [2] e0 3b [2] fb 75 [2] c6 }

  condition:
    any of them
}