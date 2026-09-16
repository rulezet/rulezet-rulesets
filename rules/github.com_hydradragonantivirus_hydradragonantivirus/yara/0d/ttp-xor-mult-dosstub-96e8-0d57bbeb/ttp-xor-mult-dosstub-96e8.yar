rule TTP_XOR_MULT_DOSStub_96e8 {
  strings:
    $key_96e8 = { c2 80 [2] b6 98 [2] f1 9a [2] b6 8b [2] f8 87 [2] f4 8d [2] e3 86 [2] f8 c8 [2] c5 }

  condition:
    any of them
}