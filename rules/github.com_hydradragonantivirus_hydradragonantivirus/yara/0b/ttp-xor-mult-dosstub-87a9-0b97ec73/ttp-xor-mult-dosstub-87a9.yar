rule TTP_XOR_MULT_DOSStub_87a9 {
  strings:
    $key_87a9 = { d3 c1 [2] a7 d9 [2] e0 db [2] a7 ca [2] e9 c6 [2] e5 cc [2] f2 c7 [2] e9 89 [2] d4 }

  condition:
    any of them
}