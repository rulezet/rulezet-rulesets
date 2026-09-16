rule TTP_XOR_MULT_DOSStub_10a4 {
  strings:
    $key_10a4 = { 44 cc [2] 30 d4 [2] 77 d6 [2] 30 c7 [2] 7e cb [2] 72 c1 [2] 65 ca [2] 7e 84 [2] 43 }

  condition:
    any of them
}