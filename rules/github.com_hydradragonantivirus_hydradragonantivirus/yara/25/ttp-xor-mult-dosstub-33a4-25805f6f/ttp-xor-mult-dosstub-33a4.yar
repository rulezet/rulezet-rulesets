rule TTP_XOR_MULT_DOSStub_33a4 {
  strings:
    $key_33a4 = { 67 cc [2] 13 d4 [2] 54 d6 [2] 13 c7 [2] 5d cb [2] 51 c1 [2] 46 ca [2] 5d 84 [2] 60 }

  condition:
    any of them
}