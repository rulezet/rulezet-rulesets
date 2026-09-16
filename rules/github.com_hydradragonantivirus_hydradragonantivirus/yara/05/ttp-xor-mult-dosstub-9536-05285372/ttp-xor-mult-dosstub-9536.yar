rule TTP_XOR_MULT_DOSStub_9536 {
  strings:
    $key_9536 = { c1 5e [2] b5 46 [2] f2 44 [2] b5 55 [2] fb 59 [2] f7 53 [2] e0 58 [2] fb 16 [2] c6 }

  condition:
    any of them
}