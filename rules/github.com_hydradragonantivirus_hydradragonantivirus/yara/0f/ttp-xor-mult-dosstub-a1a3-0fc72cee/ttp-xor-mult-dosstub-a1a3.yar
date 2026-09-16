rule TTP_XOR_MULT_DOSStub_a1a3 {
  strings:
    $key_a1a3 = { f5 cb [2] 81 d3 [2] c6 d1 [2] 81 c0 [2] cf cc [2] c3 c6 [2] d4 cd [2] cf 83 [2] f2 }

  condition:
    any of them
}