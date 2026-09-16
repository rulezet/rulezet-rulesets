rule TTP_XOR_MULT_DOSStub_14a3 {
  strings:
    $key_14a3 = { 40 cb [2] 34 d3 [2] 73 d1 [2] 34 c0 [2] 7a cc [2] 76 c6 [2] 61 cd [2] 7a 83 [2] 47 }

  condition:
    any of them
}