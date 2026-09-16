rule TTP_XOR_MULT_DOSStub_74a3 {
  strings:
    $key_74a3 = { 20 cb [2] 54 d3 [2] 13 d1 [2] 54 c0 [2] 1a cc [2] 16 c6 [2] 01 cd [2] 1a 83 [2] 27 }

  condition:
    any of them
}