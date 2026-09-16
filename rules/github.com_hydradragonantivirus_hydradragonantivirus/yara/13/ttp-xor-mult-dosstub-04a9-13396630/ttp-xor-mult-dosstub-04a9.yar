rule TTP_XOR_MULT_DOSStub_04a9 {
  strings:
    $key_04a9 = { 50 c1 [2] 24 d9 [2] 63 db [2] 24 ca [2] 6a c6 [2] 66 cc [2] 71 c7 [2] 6a 89 [2] 57 }

  condition:
    any of them
}