rule TTP_XOR_MULT_DOSStub_a7a4 {
  strings:
    $key_a7a4 = { f3 cc [2] 87 d4 [2] c0 d6 [2] 87 c7 [2] c9 cb [2] c5 c1 [2] d2 ca [2] c9 84 [2] f4 }

  condition:
    any of them
}