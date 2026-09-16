rule TTP_XOR_MULT_DOSStub_15a3 {
  strings:
    $key_15a3 = { 41 cb [2] 35 d3 [2] 72 d1 [2] 35 c0 [2] 7b cc [2] 77 c6 [2] 60 cd [2] 7b 83 [2] 46 }

  condition:
    any of them
}