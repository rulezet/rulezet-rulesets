rule TTP_XOR_MULT_DOSStub_9003 {
  strings:
    $key_9003 = { c4 6b [2] b0 73 [2] f7 71 [2] b0 60 [2] fe 6c [2] f2 66 [2] e5 6d [2] fe 23 [2] c3 }

  condition:
    any of them
}