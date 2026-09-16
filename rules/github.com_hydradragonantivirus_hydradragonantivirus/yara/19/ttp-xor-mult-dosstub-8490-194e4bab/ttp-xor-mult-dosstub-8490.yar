rule TTP_XOR_MULT_DOSStub_8490 {
  strings:
    $key_8490 = { d0 f8 [2] a4 e0 [2] e3 e2 [2] a4 f3 [2] ea ff [2] e6 f5 [2] f1 fe [2] ea b0 [2] d7 }

  condition:
    any of them
}