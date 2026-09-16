rule TTP_XOR_MULT_DOSStub_83a6 {
  strings:
    $key_83a6 = { d7 ce [2] a3 d6 [2] e4 d4 [2] a3 c5 [2] ed c9 [2] e1 c3 [2] f6 c8 [2] ed 86 [2] d0 }

  condition:
    any of them
}