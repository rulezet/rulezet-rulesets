rule TTP_XOR_MULT_DOSStub_9570 {
  strings:
    $key_9570 = { c1 18 [2] b5 00 [2] f2 02 [2] b5 13 [2] fb 1f [2] f7 15 [2] e0 1e [2] fb 50 [2] c6 }

  condition:
    any of them
}