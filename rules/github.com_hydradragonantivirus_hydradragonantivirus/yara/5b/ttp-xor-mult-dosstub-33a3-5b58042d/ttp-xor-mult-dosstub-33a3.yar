rule TTP_XOR_MULT_DOSStub_33a3 {
  strings:
    $key_33a3 = { 67 cb [2] 13 d3 [2] 54 d1 [2] 13 c0 [2] 5d cc [2] 51 c6 [2] 46 cd [2] 5d 83 [2] 60 }

  condition:
    any of them
}