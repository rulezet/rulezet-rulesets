rule TTP_XOR_MULT_DOSStub_33a9 {
  strings:
    $key_33a9 = { 67 c1 [2] 13 d9 [2] 54 db [2] 13 ca [2] 5d c6 [2] 51 cc [2] 46 c7 [2] 5d 89 [2] 60 }

  condition:
    any of them
}