rule TTP_XOR_MULT_DOSStub_a6a8 {
  strings:
    $key_a6a8 = { f2 c0 [2] 86 d8 [2] c1 da [2] 86 cb [2] c8 c7 [2] c4 cd [2] d3 c6 [2] c8 88 [2] f5 }

  condition:
    any of them
}