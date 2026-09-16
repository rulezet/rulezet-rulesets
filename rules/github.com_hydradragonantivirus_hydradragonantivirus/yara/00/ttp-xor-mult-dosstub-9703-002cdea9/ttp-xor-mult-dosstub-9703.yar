rule TTP_XOR_MULT_DOSStub_9703 {
  strings:
    $key_9703 = { c3 6b [2] b7 73 [2] f0 71 [2] b7 60 [2] f9 6c [2] f5 66 [2] e2 6d [2] f9 23 [2] c4 }

  condition:
    any of them
}