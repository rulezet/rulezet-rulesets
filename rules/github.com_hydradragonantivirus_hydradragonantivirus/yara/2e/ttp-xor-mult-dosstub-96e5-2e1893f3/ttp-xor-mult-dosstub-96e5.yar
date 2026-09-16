rule TTP_XOR_MULT_DOSStub_96e5 {
  strings:
    $key_96e5 = { c2 8d [2] b6 95 [2] f1 97 [2] b6 86 [2] f8 8a [2] f4 80 [2] e3 8b [2] f8 c5 [2] c5 }

  condition:
    any of them
}