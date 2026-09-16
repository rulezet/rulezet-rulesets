rule TTP_XOR_MULT_DOSStub_96ae {
  strings:
    $key_96ae = { c2 c6 [2] b6 de [2] f1 dc [2] b6 cd [2] f8 c1 [2] f4 cb [2] e3 c0 [2] f8 8e [2] c5 }

  condition:
    any of them
}