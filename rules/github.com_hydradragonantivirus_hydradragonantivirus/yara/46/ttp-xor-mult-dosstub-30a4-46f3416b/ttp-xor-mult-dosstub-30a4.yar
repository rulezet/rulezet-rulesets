rule TTP_XOR_MULT_DOSStub_30a4 {
  strings:
    $key_30a4 = { 64 cc [2] 10 d4 [2] 57 d6 [2] 10 c7 [2] 5e cb [2] 52 c1 [2] 45 ca [2] 5e 84 [2] 63 }

  condition:
    any of them
}