rule TTP_XOR_MULT_DOSStub_04a3 {
  strings:
    $key_04a3 = { 50 cb [2] 24 d3 [2] 63 d1 [2] 24 c0 [2] 6a cc [2] 66 c6 [2] 71 cd [2] 6a 83 [2] 57 }

  condition:
    any of them
}