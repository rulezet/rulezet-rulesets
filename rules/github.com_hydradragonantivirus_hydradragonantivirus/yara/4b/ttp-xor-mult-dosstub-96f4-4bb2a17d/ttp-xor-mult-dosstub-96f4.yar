rule TTP_XOR_MULT_DOSStub_96f4 {
  strings:
    $key_96f4 = { c2 9c [2] b6 84 [2] f1 86 [2] b6 97 [2] f8 9b [2] f4 91 [2] e3 9a [2] f8 d4 [2] c5 }

  condition:
    any of them
}