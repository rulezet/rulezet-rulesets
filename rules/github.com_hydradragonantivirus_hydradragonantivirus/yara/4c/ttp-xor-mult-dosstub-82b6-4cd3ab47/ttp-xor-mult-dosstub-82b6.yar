rule TTP_XOR_MULT_DOSStub_82b6 {
  strings:
    $key_82b6 = { d6 de [2] a2 c6 [2] e5 c4 [2] a2 d5 [2] ec d9 [2] e0 d3 [2] f7 d8 [2] ec 96 [2] d1 }

  condition:
    any of them
}