rule TTP_XOR_MULT_DOSStub_74a4 {
  strings:
    $key_74a4 = { 20 cc [2] 54 d4 [2] 13 d6 [2] 54 c7 [2] 1a cb [2] 16 c1 [2] 01 ca [2] 1a 84 [2] 27 }

  condition:
    any of them
}