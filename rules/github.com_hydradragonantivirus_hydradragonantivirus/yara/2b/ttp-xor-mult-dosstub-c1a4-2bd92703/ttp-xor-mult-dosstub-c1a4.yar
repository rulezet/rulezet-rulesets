rule TTP_XOR_MULT_DOSStub_c1a4 {
  strings:
    $key_c1a4 = { 95 cc [2] e1 d4 [2] a6 d6 [2] e1 c7 [2] af cb [2] a3 c1 [2] b4 ca [2] af 84 [2] 92 }

  condition:
    any of them
}