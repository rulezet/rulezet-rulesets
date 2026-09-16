rule TTP_XOR_MULT_DOSStub_97ae {
  strings:
    $key_97ae = { c3 c6 [2] b7 de [2] f0 dc [2] b7 cd [2] f9 c1 [2] f5 cb [2] e2 c0 [2] f9 8e [2] c4 }

  condition:
    any of them
}