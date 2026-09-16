rule TTP_XOR_MULT_DOSStub_35a9 {
  strings:
    $key_35a9 = { 61 c1 [2] 15 d9 [2] 52 db [2] 15 ca [2] 5b c6 [2] 57 cc [2] 40 c7 [2] 5b 89 [2] 66 }

  condition:
    any of them
}