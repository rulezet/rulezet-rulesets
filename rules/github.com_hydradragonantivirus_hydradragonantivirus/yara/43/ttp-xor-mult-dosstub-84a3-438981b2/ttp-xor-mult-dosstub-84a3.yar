rule TTP_XOR_MULT_DOSStub_84a3 {
  strings:
    $key_84a3 = { d0 cb [2] a4 d3 [2] e3 d1 [2] a4 c0 [2] ea cc [2] e6 c6 [2] f1 cd [2] ea 83 [2] d7 }

  condition:
    any of them
}