rule TTP_XOR_MULT_DOSStub_82b0 {
  strings:
    $key_82b0 = { d6 d8 [2] a2 c0 [2] e5 c2 [2] a2 d3 [2] ec df [2] e0 d5 [2] f7 de [2] ec 90 [2] d1 }

  condition:
    any of them
}