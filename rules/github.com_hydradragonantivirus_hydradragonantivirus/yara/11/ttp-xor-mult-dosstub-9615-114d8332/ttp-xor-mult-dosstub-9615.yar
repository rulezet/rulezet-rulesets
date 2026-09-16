rule TTP_XOR_MULT_DOSStub_9615 {
  strings:
    $key_9615 = { c2 7d [2] b6 65 [2] f1 67 [2] b6 76 [2] f8 7a [2] f4 70 [2] e3 7b [2] f8 35 [2] c5 }

  condition:
    any of them
}