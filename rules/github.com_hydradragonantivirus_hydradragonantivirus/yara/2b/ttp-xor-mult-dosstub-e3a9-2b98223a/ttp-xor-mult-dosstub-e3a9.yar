rule TTP_XOR_MULT_DOSStub_e3a9 {
  strings:
    $key_e3a9 = { b7 c1 [2] c3 d9 [2] 84 db [2] c3 ca [2] 8d c6 [2] 81 cc [2] 96 c7 [2] 8d 89 [2] b0 }

  condition:
    any of them
}