rule TTP_XOR_MULT_DOSStub_96f8 {
  strings:
    $key_96f8 = { c2 90 [2] b6 88 [2] f1 8a [2] b6 9b [2] f8 97 [2] f4 9d [2] e3 96 [2] f8 d8 [2] c5 }

  condition:
    any of them
}