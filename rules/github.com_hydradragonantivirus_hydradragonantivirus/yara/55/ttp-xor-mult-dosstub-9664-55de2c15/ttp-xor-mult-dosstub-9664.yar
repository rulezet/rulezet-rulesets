rule TTP_XOR_MULT_DOSStub_9664 {
  strings:
    $key_9664 = { c2 0c [2] b6 14 [2] f1 16 [2] b6 07 [2] f8 0b [2] f4 01 [2] e3 0a [2] f8 44 [2] c5 }

  condition:
    any of them
}