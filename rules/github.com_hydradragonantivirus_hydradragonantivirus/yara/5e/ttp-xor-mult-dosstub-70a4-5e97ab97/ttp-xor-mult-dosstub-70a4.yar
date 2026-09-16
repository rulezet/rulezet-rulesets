rule TTP_XOR_MULT_DOSStub_70a4 {
  strings:
    $key_70a4 = { 24 cc [2] 50 d4 [2] 17 d6 [2] 50 c7 [2] 1e cb [2] 12 c1 [2] 05 ca [2] 1e 84 [2] 23 }

  condition:
    any of them
}