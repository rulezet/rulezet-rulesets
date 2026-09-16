rule TTP_XOR_MULT_DOSStub_73a3 {
  strings:
    $key_73a3 = { 27 cb [2] 53 d3 [2] 14 d1 [2] 53 c0 [2] 1d cc [2] 11 c6 [2] 06 cd [2] 1d 83 [2] 20 }

  condition:
    any of them
}