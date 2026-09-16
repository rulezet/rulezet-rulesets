rule TTP_XOR_MULT_DOSStub_a6a5 {
  strings:
    $key_a6a5 = { f2 cd [2] 86 d5 [2] c1 d7 [2] 86 c6 [2] c8 ca [2] c4 c0 [2] d3 cb [2] c8 85 [2] f5 }

  condition:
    any of them
}