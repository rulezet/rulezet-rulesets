rule TTP_XOR_MULT_DOSStub_83a9 {
  strings:
    $key_83a9 = { d7 c1 [2] a3 d9 [2] e4 db [2] a3 ca [2] ed c6 [2] e1 cc [2] f6 c7 [2] ed 89 [2] d0 }

  condition:
    any of them
}