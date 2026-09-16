rule TTP_XOR_MULT_DOSStub_9577 {
  strings:
    $key_9577 = { c1 1f [2] b5 07 [2] f2 05 [2] b5 14 [2] fb 18 [2] f7 12 [2] e0 19 [2] fb 57 [2] c6 }

  condition:
    any of them
}