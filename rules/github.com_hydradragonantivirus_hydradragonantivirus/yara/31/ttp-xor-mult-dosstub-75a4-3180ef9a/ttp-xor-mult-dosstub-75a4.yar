rule TTP_XOR_MULT_DOSStub_75a4 {
  strings:
    $key_75a4 = { 21 cc [2] 55 d4 [2] 12 d6 [2] 55 c7 [2] 1b cb [2] 17 c1 [2] 00 ca [2] 1b 84 [2] 26 }

  condition:
    any of them
}