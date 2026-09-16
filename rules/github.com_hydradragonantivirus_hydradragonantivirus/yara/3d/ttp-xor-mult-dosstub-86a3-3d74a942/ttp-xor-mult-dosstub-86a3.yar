rule TTP_XOR_MULT_DOSStub_86a3 {
  strings:
    $key_86a3 = { d2 cb [2] a6 d3 [2] e1 d1 [2] a6 c0 [2] e8 cc [2] e4 c6 [2] f3 cd [2] e8 83 [2] d5 }

  condition:
    any of them
}