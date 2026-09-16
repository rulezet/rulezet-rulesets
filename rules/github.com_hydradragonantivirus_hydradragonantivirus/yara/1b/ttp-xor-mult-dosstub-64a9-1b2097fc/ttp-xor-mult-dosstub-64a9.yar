rule TTP_XOR_MULT_DOSStub_64a9 {
  strings:
    $key_64a9 = { 30 c1 [2] 44 d9 [2] 03 db [2] 44 ca [2] 0a c6 [2] 06 cc [2] 11 c7 [2] 0a 89 [2] 37 }

  condition:
    any of them
}