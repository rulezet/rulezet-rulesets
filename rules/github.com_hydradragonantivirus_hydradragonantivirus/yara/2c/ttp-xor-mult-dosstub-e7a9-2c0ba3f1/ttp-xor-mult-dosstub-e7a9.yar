rule TTP_XOR_MULT_DOSStub_e7a9 {
  strings:
    $key_e7a9 = { b3 c1 [2] c7 d9 [2] 80 db [2] c7 ca [2] 89 c6 [2] 85 cc [2] 92 c7 [2] 89 89 [2] b4 }

  condition:
    any of them
}