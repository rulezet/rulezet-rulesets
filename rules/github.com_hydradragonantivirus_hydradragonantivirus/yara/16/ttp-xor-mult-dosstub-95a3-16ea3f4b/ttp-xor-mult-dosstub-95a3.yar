rule TTP_XOR_MULT_DOSStub_95a3 {
  strings:
    $key_95a3 = { c1 cb [2] b5 d3 [2] f2 d1 [2] b5 c0 [2] fb cc [2] f7 c6 [2] e0 cd [2] fb 83 [2] c6 }

  condition:
    any of them
}