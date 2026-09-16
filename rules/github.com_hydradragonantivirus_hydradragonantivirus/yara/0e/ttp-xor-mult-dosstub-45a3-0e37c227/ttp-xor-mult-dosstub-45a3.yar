rule TTP_XOR_MULT_DOSStub_45a3 {
  strings:
    $key_45a3 = { 11 cb [2] 65 d3 [2] 22 d1 [2] 65 c0 [2] 2b cc [2] 27 c6 [2] 30 cd [2] 2b 83 [2] 16 }

  condition:
    any of them
}