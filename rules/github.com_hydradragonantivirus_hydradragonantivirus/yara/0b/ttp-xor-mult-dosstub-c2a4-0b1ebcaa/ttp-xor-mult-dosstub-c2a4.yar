rule TTP_XOR_MULT_DOSStub_c2a4 {
  strings:
    $key_c2a4 = { 96 cc [2] e2 d4 [2] a5 d6 [2] e2 c7 [2] ac cb [2] a0 c1 [2] b7 ca [2] ac 84 [2] 91 }

  condition:
    any of them
}