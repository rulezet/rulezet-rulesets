rule TTP_XOR_MULT_DOSStub_03a9 {
  strings:
    $key_03a9 = { 57 c1 [2] 23 d9 [2] 64 db [2] 23 ca [2] 6d c6 [2] 61 cc [2] 76 c7 [2] 6d 89 [2] 50 }

  condition:
    any of them
}