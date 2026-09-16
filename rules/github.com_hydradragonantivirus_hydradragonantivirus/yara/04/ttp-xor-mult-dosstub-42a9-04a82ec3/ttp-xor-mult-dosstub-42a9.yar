rule TTP_XOR_MULT_DOSStub_42a9 {
  strings:
    $key_42a9 = { 16 c1 [2] 62 d9 [2] 25 db [2] 62 ca [2] 2c c6 [2] 20 cc [2] 37 c7 [2] 2c 89 [2] 11 }

  condition:
    any of them
}