rule TTP_XOR_MULT_DOSStub_97a8 {
  strings:
    $key_97a8 = { c3 c0 [2] b7 d8 [2] f0 da [2] b7 cb [2] f9 c7 [2] f5 cd [2] e2 c6 [2] f9 88 [2] c4 }

  condition:
    any of them
}