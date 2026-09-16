rule TTP_XOR_MULT_DOSStub_9566 {
  strings:
    $key_9566 = { c1 0e [2] b5 16 [2] f2 14 [2] b5 05 [2] fb 09 [2] f7 03 [2] e0 08 [2] fb 46 [2] c6 }

  condition:
    any of them
}