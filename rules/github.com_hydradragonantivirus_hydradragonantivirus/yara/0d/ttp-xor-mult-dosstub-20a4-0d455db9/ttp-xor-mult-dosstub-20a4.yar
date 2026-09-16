rule TTP_XOR_MULT_DOSStub_20a4 {
  strings:
    $key_20a4 = { 74 cc [2] 00 d4 [2] 47 d6 [2] 00 c7 [2] 4e cb [2] 42 c1 [2] 55 ca [2] 4e 84 [2] 73 }

  condition:
    any of them
}