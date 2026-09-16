rule TTP_XOR_MULT_DOSStub_95b0 {
  strings:
    $key_95b0 = { c1 d8 [2] b5 c0 [2] f2 c2 [2] b5 d3 [2] fb df [2] f7 d5 [2] e0 de [2] fb 90 [2] c6 }

  condition:
    any of them
}