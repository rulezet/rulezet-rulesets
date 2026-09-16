rule TTP_XOR_MULT_DOSStub_f1a4 {
  strings:
    $key_f1a4 = { a5 cc [2] d1 d4 [2] 96 d6 [2] d1 c7 [2] 9f cb [2] 93 c1 [2] 84 ca [2] 9f 84 [2] a2 }

  condition:
    any of them
}