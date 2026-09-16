rule TTP_XOR_MULT_DOSStub_23a3 {
  strings:
    $key_23a3 = { 77 cb [2] 03 d3 [2] 44 d1 [2] 03 c0 [2] 4d cc [2] 41 c6 [2] 56 cd [2] 4d 83 [2] 70 }

  condition:
    any of them
}