rule TTP_XOR_MULT_DOSStub_03a3 {
  strings:
    $key_03a3 = { 57 cb [2] 23 d3 [2] 64 d1 [2] 23 c0 [2] 6d cc [2] 61 c6 [2] 76 cd [2] 6d 83 [2] 50 }

  condition:
    any of them
}