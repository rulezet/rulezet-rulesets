rule TTP_XOR_MULT_DOSStub_96fc {
  strings:
    $key_96fc = { c2 94 [2] b6 8c [2] f1 8e [2] b6 9f [2] f8 93 [2] f4 99 [2] e3 92 [2] f8 dc [2] c5 }

  condition:
    any of them
}