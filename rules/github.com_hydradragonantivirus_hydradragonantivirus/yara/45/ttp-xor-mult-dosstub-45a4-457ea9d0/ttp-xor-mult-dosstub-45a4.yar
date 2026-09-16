rule TTP_XOR_MULT_DOSStub_45a4 {
  strings:
    $key_45a4 = { 11 cc [2] 65 d4 [2] 22 d6 [2] 65 c7 [2] 2b cb [2] 27 c1 [2] 30 ca [2] 2b 84 [2] 16 }

  condition:
    any of them
}