rule TTP_XOR_MULT_DOSStub_96f9 {
  strings:
    $key_96f9 = { c2 91 [2] b6 89 [2] f1 8b [2] b6 9a [2] f8 96 [2] f4 9c [2] e3 97 [2] f8 d9 [2] c5 }

  condition:
    any of them
}