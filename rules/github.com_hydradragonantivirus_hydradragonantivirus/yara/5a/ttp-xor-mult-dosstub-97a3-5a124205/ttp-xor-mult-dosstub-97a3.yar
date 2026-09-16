rule TTP_XOR_MULT_DOSStub_97a3 {
  strings:
    $key_97a3 = { c3 cb [2] b7 d3 [2] f0 d1 [2] b7 c0 [2] f9 cc [2] f5 c6 [2] e2 cd [2] f9 83 [2] c4 }

  condition:
    any of them
}