rule TTP_XOR_MULT_DOSStub_9505 {
  strings:
    $key_9505 = { c1 6d [2] b5 75 [2] f2 77 [2] b5 66 [2] fb 6a [2] f7 60 [2] e0 6b [2] fb 25 [2] c6 }

  condition:
    any of them
}