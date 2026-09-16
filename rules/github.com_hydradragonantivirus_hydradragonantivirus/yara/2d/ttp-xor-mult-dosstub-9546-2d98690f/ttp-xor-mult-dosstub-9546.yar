rule TTP_XOR_MULT_DOSStub_9546 {
  strings:
    $key_9546 = { c1 2e [2] b5 36 [2] f2 34 [2] b5 25 [2] fb 29 [2] f7 23 [2] e0 28 [2] fb 66 [2] c6 }

  condition:
    any of them
}