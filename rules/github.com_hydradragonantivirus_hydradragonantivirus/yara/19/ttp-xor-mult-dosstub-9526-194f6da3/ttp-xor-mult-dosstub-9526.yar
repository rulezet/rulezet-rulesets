rule TTP_XOR_MULT_DOSStub_9526 {
  strings:
    $key_9526 = { c1 4e [2] b5 56 [2] f2 54 [2] b5 45 [2] fb 49 [2] f7 43 [2] e0 48 [2] fb 06 [2] c6 }

  condition:
    any of them
}