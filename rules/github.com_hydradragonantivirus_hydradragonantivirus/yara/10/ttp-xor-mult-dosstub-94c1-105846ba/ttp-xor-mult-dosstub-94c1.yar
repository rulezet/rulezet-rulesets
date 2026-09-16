rule TTP_XOR_MULT_DOSStub_94c1 {
  strings:
    $key_94c1 = { c0 a9 [2] b4 b1 [2] f3 b3 [2] b4 a2 [2] fa ae [2] f6 a4 [2] e1 af [2] fa e1 [2] c7 }

  condition:
    any of them
}