rule TTP_XOR_MULT_DOSStub_9545 {
  strings:
    $key_9545 = { c1 2d [2] b5 35 [2] f2 37 [2] b5 26 [2] fb 2a [2] f7 20 [2] e0 2b [2] fb 65 [2] c6 }

  condition:
    any of them
}