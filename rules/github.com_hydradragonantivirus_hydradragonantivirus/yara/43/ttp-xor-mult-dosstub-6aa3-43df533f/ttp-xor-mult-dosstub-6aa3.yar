rule TTP_XOR_MULT_DOSStub_6aa3 {
  strings:
    $key_6aa3 = { 3e cb [2] 4a d3 [2] 0d d1 [2] 4a c0 [2] 04 cc [2] 08 c6 [2] 1f cd [2] 04 83 [2] 39 }

  condition:
    any of them
}