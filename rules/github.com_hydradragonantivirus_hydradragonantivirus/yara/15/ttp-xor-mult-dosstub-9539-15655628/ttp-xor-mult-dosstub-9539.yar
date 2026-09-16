rule TTP_XOR_MULT_DOSStub_9539 {
  strings:
    $key_9539 = { c1 51 [2] b5 49 [2] f2 4b [2] b5 5a [2] fb 56 [2] f7 5c [2] e0 57 [2] fb 19 [2] c6 }

  condition:
    any of them
}