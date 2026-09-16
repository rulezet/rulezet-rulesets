rule TTP_XOR_MULT_DOSStub_85c7 {
  strings:
    $key_85c7 = { d1 af [2] a5 b7 [2] e2 b5 [2] a5 a4 [2] eb a8 [2] e7 a2 [2] f0 a9 [2] eb e7 [2] d6 }

  condition:
    any of them
}