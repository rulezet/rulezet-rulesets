rule TTP_XOR_MULT_DOSStub_e2a2 {
  strings:
    $key_e2a2 = { b6 ca [2] c2 d2 [2] 85 d0 [2] c2 c1 [2] 8c cd [2] 80 c7 [2] 97 cc [2] 8c 82 [2] b1 }

  condition:
    any of them
}