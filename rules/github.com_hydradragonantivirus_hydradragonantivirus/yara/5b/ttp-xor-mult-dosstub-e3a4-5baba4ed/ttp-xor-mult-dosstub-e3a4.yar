rule TTP_XOR_MULT_DOSStub_e3a4 {
  strings:
    $key_e3a4 = { b7 cc [2] c3 d4 [2] 84 d6 [2] c3 c7 [2] 8d cb [2] 81 c1 [2] 96 ca [2] 8d 84 [2] b0 }

  condition:
    any of them
}