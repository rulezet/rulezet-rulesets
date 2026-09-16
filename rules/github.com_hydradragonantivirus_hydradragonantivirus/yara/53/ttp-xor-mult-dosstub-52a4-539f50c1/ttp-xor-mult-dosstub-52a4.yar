rule TTP_XOR_MULT_DOSStub_52a4 {
  strings:
    $key_52a4 = { 06 cc [2] 72 d4 [2] 35 d6 [2] 72 c7 [2] 3c cb [2] 30 c1 [2] 27 ca [2] 3c 84 [2] 01 }

  condition:
    any of them
}