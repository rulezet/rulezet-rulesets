rule TTP_XOR_MULT_DOSStub_c1a9 {
  strings:
    $key_c1a9 = { 95 c1 [2] e1 d9 [2] a6 db [2] e1 ca [2] af c6 [2] a3 cc [2] b4 c7 [2] af 89 [2] 92 }

  condition:
    any of them
}