rule TTP_XOR_MULT_DOSStub_9776 {
  strings:
    $key_9776 = { c3 1e [2] b7 06 [2] f0 04 [2] b7 15 [2] f9 19 [2] f5 13 [2] e2 18 [2] f9 56 [2] c4 }

  condition:
    any of them
}