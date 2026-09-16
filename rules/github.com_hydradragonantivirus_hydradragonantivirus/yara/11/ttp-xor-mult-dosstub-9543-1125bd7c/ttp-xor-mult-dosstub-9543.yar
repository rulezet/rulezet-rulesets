rule TTP_XOR_MULT_DOSStub_9543 {
  strings:
    $key_9543 = { c1 2b [2] b5 33 [2] f2 31 [2] b5 20 [2] fb 2c [2] f7 26 [2] e0 2d [2] fb 63 [2] c6 }

  condition:
    any of them
}