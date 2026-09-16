rule TTP_XOR_MULT_DOSStub_f1a9 {
  strings:
    $key_f1a9 = { a5 c1 [2] d1 d9 [2] 96 db [2] d1 ca [2] 9f c6 [2] 93 cc [2] 84 c7 [2] 9f 89 [2] a2 }

  condition:
    any of them
}