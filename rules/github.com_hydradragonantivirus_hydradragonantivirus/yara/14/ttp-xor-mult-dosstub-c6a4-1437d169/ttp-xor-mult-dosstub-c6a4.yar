rule TTP_XOR_MULT_DOSStub_c6a4 {
  strings:
    $key_c6a4 = { 92 cc [2] e6 d4 [2] a1 d6 [2] e6 c7 [2] a8 cb [2] a4 c1 [2] b3 ca [2] a8 84 [2] 95 }

  condition:
    any of them
}