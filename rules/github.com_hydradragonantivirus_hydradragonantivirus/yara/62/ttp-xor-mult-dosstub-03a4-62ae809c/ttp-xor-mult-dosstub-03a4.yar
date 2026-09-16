rule TTP_XOR_MULT_DOSStub_03a4 {
  strings:
    $key_03a4 = { 57 cc [2] 23 d4 [2] 64 d6 [2] 23 c7 [2] 6d cb [2] 61 c1 [2] 76 ca [2] 6d 84 [2] 50 }

  condition:
    any of them
}