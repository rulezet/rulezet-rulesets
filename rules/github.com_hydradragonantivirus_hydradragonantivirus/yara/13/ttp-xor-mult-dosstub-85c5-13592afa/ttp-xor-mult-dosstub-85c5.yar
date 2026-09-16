rule TTP_XOR_MULT_DOSStub_85c5 {
  strings:
    $key_85c5 = { d1 ad [2] a5 b5 [2] e2 b7 [2] a5 a6 [2] eb aa [2] e7 a0 [2] f0 ab [2] eb e5 [2] d6 }

  condition:
    any of them
}