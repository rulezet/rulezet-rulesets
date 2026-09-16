rule TTP_XOR_MULT_DOSStub_13a9 {
  strings:
    $key_13a9 = { 47 c1 [2] 33 d9 [2] 74 db [2] 33 ca [2] 7d c6 [2] 71 cc [2] 66 c7 [2] 7d 89 [2] 40 }

  condition:
    any of them
}