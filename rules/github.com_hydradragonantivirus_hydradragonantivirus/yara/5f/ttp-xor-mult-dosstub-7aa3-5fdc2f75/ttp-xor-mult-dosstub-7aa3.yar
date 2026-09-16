rule TTP_XOR_MULT_DOSStub_7aa3 {
  strings:
    $key_7aa3 = { 2e cb [2] 5a d3 [2] 1d d1 [2] 5a c0 [2] 14 cc [2] 18 c6 [2] 0f cd [2] 14 83 [2] 29 }

  condition:
    any of them
}