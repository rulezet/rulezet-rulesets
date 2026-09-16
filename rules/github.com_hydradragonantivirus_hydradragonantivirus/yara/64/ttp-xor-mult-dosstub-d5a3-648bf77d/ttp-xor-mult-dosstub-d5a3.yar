rule TTP_XOR_MULT_DOSStub_d5a3 {
  strings:
    $key_d5a3 = { 81 cb [2] f5 d3 [2] b2 d1 [2] f5 c0 [2] bb cc [2] b7 c6 [2] a0 cd [2] bb 83 [2] 86 }

  condition:
    any of them
}