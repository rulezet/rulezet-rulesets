rule TTP_XOR_MULT_DOSStub_9518 {
  strings:
    $key_9518 = { c1 70 [2] b5 68 [2] f2 6a [2] b5 7b [2] fb 77 [2] f7 7d [2] e0 76 [2] fb 38 [2] c6 }

  condition:
    any of them
}