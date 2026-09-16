rule TTP_XOR_MULT_DOSStub_40a3 {
  strings:
    $key_40a3 = { 14 cb [2] 60 d3 [2] 27 d1 [2] 60 c0 [2] 2e cc [2] 22 c6 [2] 35 cd [2] 2e 83 [2] 13 }

  condition:
    any of them
}