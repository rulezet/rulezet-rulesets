rule TTP_XOR_MULT_DOSStub_63a4 {
  strings:
    $key_63a4 = { 37 cc [2] 43 d4 [2] 04 d6 [2] 43 c7 [2] 0d cb [2] 01 c1 [2] 16 ca [2] 0d 84 [2] 30 }

  condition:
    any of them
}