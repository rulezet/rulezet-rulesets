rule TTP_XOR_MULT_DOSStub_a6a3 {
  strings:
    $key_a6a3 = { f2 cb [2] 86 d3 [2] c1 d1 [2] 86 c0 [2] c8 cc [2] c4 c6 [2] d3 cd [2] c8 83 [2] f5 }

  condition:
    any of them
}