rule TTP_XOR_MULT_DOSStub_87a4 {
  strings:
    $key_87a4 = { d3 cc [2] a7 d4 [2] e0 d6 [2] a7 c7 [2] e9 cb [2] e5 c1 [2] f2 ca [2] e9 84 [2] d4 }

  condition:
    any of them
}