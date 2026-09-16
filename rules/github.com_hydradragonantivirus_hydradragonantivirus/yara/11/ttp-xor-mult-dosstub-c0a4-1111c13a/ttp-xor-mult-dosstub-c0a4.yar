rule TTP_XOR_MULT_DOSStub_c0a4 {
  strings:
    $key_c0a4 = { 94 cc [2] e0 d4 [2] a7 d6 [2] e0 c7 [2] ae cb [2] a2 c1 [2] b5 ca [2] ae 84 [2] 93 }

  condition:
    any of them
}