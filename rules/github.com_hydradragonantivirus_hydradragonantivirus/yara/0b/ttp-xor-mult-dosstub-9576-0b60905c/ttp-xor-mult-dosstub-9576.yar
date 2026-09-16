rule TTP_XOR_MULT_DOSStub_9576 {
  strings:
    $key_9576 = { c1 1e [2] b5 06 [2] f2 04 [2] b5 15 [2] fb 19 [2] f7 13 [2] e0 18 [2] fb 56 [2] c6 }

  condition:
    any of them
}