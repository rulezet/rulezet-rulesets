rule TTP_XOR_MULT_DOSStub_9774 {
  strings:
    $key_9774 = { c3 1c [2] b7 04 [2] f0 06 [2] b7 17 [2] f9 1b [2] f5 11 [2] e2 1a [2] f9 54 [2] c4 }

  condition:
    any of them
}