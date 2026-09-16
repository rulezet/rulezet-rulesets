rule TTP_XOR_MULT_DOSStub_71a4 {
  strings:
    $key_71a4 = { 25 cc [2] 51 d4 [2] 16 d6 [2] 51 c7 [2] 1f cb [2] 13 c1 [2] 04 ca [2] 1f 84 [2] 22 }

  condition:
    any of them
}