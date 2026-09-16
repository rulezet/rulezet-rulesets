rule TTP_XOR_MULT_DOSStub_25a3 {
  strings:
    $key_25a3 = { 71 cb [2] 05 d3 [2] 42 d1 [2] 05 c0 [2] 4b cc [2] 47 c6 [2] 50 cd [2] 4b 83 [2] 76 }

  condition:
    any of them
}