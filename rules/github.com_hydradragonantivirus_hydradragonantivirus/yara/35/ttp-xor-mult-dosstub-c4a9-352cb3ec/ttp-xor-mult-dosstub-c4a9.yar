rule TTP_XOR_MULT_DOSStub_c4a9 {
  strings:
    $key_c4a9 = { 90 c1 [2] e4 d9 [2] a3 db [2] e4 ca [2] aa c6 [2] a6 cc [2] b1 c7 [2] aa 89 [2] 97 }

  condition:
    any of them
}