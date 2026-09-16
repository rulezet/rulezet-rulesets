rule TTP_XOR_MULT_DOSStub_94a3 {
  strings:
    $key_94a3 = { c0 cb [2] b4 d3 [2] f3 d1 [2] b4 c0 [2] fa cc [2] f6 c6 [2] e1 cd [2] fa 83 [2] c7 }

  condition:
    any of them
}