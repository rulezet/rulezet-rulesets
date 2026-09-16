rule TTP_XOR_MULT_DOSStub_75a9 {
  strings:
    $key_75a9 = { 21 c1 [2] 55 d9 [2] 12 db [2] 55 ca [2] 1b c6 [2] 17 cc [2] 00 c7 [2] 1b 89 [2] 26 }

  condition:
    any of them
}