rule TTP_XOR_MULT_DOSStub_94b0 {
  strings:
    $key_94b0 = { c0 d8 [2] b4 c0 [2] f3 c2 [2] b4 d3 [2] fa df [2] f6 d5 [2] e1 de [2] fa 90 [2] c7 }

  condition:
    any of them
}