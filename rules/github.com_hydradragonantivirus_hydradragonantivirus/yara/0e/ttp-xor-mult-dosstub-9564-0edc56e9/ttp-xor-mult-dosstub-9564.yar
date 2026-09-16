rule TTP_XOR_MULT_DOSStub_9564 {
  strings:
    $key_9564 = { c1 0c [2] b5 14 [2] f2 16 [2] b5 07 [2] fb 0b [2] f7 01 [2] e0 0a [2] fb 44 [2] c6 }

  condition:
    any of them
}