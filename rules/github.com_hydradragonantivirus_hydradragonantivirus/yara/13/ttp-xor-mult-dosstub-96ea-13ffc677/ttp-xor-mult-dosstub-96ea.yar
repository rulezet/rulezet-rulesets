rule TTP_XOR_MULT_DOSStub_96ea {
  strings:
    $key_96ea = { c2 82 [2] b6 9a [2] f1 98 [2] b6 89 [2] f8 85 [2] f4 8f [2] e3 84 [2] f8 ca [2] c5 }

  condition:
    any of them
}