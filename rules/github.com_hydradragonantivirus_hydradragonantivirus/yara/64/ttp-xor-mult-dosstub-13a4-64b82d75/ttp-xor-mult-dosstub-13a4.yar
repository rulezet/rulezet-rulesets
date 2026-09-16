rule TTP_XOR_MULT_DOSStub_13a4 {
  strings:
    $key_13a4 = { 47 cc [2] 33 d4 [2] 74 d6 [2] 33 c7 [2] 7d cb [2] 71 c1 [2] 66 ca [2] 7d 84 [2] 40 }

  condition:
    any of them
}