rule TTP_XOR_MULT_DOSStub_c2a9 {
  strings:
    $key_c2a9 = { 96 c1 [2] e2 d9 [2] a5 db [2] e2 ca [2] ac c6 [2] a0 cc [2] b7 c7 [2] ac 89 [2] 91 }

  condition:
    any of them
}