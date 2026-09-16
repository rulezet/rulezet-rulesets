rule TTP_XOR_MULT_DOSStub_2aa3 {
  strings:
    $key_2aa3 = { 7e cb [2] 0a d3 [2] 4d d1 [2] 0a c0 [2] 44 cc [2] 48 c6 [2] 5f cd [2] 44 83 [2] 79 }

  condition:
    any of them
}