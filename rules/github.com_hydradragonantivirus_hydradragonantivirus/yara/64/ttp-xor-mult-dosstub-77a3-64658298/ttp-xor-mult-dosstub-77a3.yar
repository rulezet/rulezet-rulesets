rule TTP_XOR_MULT_DOSStub_77a3 {
  strings:
    $key_77a3 = { 23 cb [2] 57 d3 [2] 10 d1 [2] 57 c0 [2] 19 cc [2] 15 c6 [2] 02 cd [2] 19 83 [2] 24 }

  condition:
    any of them
}