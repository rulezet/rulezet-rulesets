rule TTP_XOR_MULT_DOSStub_9519 {
  strings:
    $key_9519 = { c1 71 [2] b5 69 [2] f2 6b [2] b5 7a [2] fb 76 [2] f7 7c [2] e0 77 [2] fb 39 [2] c6 }

  condition:
    any of them
}