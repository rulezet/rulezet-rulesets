rule TTP_XOR_MULT_DOSStub_55a3 {
  strings:
    $key_55a3 = { 01 cb [2] 75 d3 [2] 32 d1 [2] 75 c0 [2] 3b cc [2] 37 c6 [2] 20 cd [2] 3b 83 [2] 06 }

  condition:
    any of them
}