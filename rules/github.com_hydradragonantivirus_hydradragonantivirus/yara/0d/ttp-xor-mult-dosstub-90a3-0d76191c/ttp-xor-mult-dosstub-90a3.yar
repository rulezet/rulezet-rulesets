rule TTP_XOR_MULT_DOSStub_90a3 {
  strings:
    $key_90a3 = { c4 cb [2] b0 d3 [2] f7 d1 [2] b0 c0 [2] fe cc [2] f2 c6 [2] e5 cd [2] fe 83 [2] c3 }

  condition:
    any of them
}