rule TTP_XOR_MULT_DOSStub_41a4 {
  strings:
    $key_41a4 = { 15 cc [2] 61 d4 [2] 26 d6 [2] 61 c7 [2] 2f cb [2] 23 c1 [2] 34 ca [2] 2f 84 [2] 12 }

  condition:
    any of them
}