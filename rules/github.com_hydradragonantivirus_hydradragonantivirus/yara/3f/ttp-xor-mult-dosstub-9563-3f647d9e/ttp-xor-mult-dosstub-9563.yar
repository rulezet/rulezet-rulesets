rule TTP_XOR_MULT_DOSStub_9563 {
  strings:
    $key_9563 = { c1 0b [2] b5 13 [2] f2 11 [2] b5 00 [2] fb 0c [2] f7 06 [2] e0 0d [2] fb 43 [2] c6 }

  condition:
    any of them
}