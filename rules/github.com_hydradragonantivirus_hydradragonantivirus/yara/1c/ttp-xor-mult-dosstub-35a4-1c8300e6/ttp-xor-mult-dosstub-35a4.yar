rule TTP_XOR_MULT_DOSStub_35a4 {
  strings:
    $key_35a4 = { 61 cc [2] 15 d4 [2] 52 d6 [2] 15 c7 [2] 5b cb [2] 57 c1 [2] 40 ca [2] 5b 84 [2] 66 }

  condition:
    any of them
}