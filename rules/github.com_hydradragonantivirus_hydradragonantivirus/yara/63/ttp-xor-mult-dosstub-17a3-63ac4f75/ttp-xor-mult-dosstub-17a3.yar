rule TTP_XOR_MULT_DOSStub_17a3 {
  strings:
    $key_17a3 = { 43 cb [2] 37 d3 [2] 70 d1 [2] 37 c0 [2] 79 cc [2] 75 c6 [2] 62 cd [2] 79 83 [2] 44 }

  condition:
    any of them
}