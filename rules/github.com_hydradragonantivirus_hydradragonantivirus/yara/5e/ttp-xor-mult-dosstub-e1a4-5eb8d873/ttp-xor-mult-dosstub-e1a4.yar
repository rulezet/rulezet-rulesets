rule TTP_XOR_MULT_DOSStub_e1a4 {
  strings:
    $key_e1a4 = { b5 cc [2] c1 d4 [2] 86 d6 [2] c1 c7 [2] 8f cb [2] 83 c1 [2] 94 ca [2] 8f 84 [2] b2 }

  condition:
    any of them
}