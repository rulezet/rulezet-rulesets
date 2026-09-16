rule TTP_XOR_MULT_DOSStub_9503 {
  strings:
    $key_9503 = { c1 6b [2] b5 73 [2] f2 71 [2] b5 60 [2] fb 6c [2] f7 66 [2] e0 6d [2] fb 23 [2] c6 }

  condition:
    any of them
}