rule TTP_XOR_MULT_DOSStub_e2a4 {
  strings:
    $key_e2a4 = { b6 cc [2] c2 d4 [2] 85 d6 [2] c2 c7 [2] 8c cb [2] 80 c1 [2] 97 ca [2] 8c 84 [2] b1 }

  condition:
    any of them
}