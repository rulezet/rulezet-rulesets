rule TTP_XOR_MULT_DOSStub_e7a4 {
  strings:
    $key_e7a4 = { b3 cc [2] c7 d4 [2] 80 d6 [2] c7 c7 [2] 89 cb [2] 85 c1 [2] 92 ca [2] 89 84 [2] b4 }

  condition:
    any of them
}