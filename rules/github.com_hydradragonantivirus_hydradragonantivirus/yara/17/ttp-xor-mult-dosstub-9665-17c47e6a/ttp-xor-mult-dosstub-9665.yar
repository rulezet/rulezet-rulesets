rule TTP_XOR_MULT_DOSStub_9665 {
  strings:
    $key_9665 = { c2 0d [2] b6 15 [2] f1 17 [2] b6 06 [2] f8 0a [2] f4 00 [2] e3 0b [2] f8 45 [2] c5 }

  condition:
    any of them
}