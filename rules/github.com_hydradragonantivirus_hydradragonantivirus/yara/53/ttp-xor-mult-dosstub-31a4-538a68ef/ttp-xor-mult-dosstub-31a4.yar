rule TTP_XOR_MULT_DOSStub_31a4 {
  strings:
    $key_31a4 = { 65 cc [2] 11 d4 [2] 56 d6 [2] 11 c7 [2] 5f cb [2] 53 c1 [2] 44 ca [2] 5f 84 [2] 62 }

  condition:
    any of them
}