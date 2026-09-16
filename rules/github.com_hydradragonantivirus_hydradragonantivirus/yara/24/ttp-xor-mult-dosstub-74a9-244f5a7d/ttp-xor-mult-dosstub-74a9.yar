rule TTP_XOR_MULT_DOSStub_74a9 {
  strings:
    $key_74a9 = { 20 c1 [2] 54 d9 [2] 13 db [2] 54 ca [2] 1a c6 [2] 16 cc [2] 01 c7 [2] 1a 89 [2] 27 }

  condition:
    any of them
}