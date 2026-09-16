rule TTP_XOR_MULT_DOSStub_9548 {
  strings:
    $key_9548 = { c1 20 [2] b5 38 [2] f2 3a [2] b5 2b [2] fb 27 [2] f7 2d [2] e0 26 [2] fb 68 [2] c6 }

  condition:
    any of them
}