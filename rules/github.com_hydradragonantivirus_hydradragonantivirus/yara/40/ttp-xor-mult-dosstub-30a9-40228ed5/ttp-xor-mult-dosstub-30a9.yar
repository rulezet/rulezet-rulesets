rule TTP_XOR_MULT_DOSStub_30a9 {
  strings:
    $key_30a9 = { 64 c1 [2] 10 d9 [2] 57 db [2] 10 ca [2] 5e c6 [2] 52 cc [2] 45 c7 [2] 5e 89 [2] 63 }

  condition:
    any of them
}