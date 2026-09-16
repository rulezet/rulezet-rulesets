rule TTP_XOR_MULT_DOSStub_11a3 {
  strings:
    $key_11a3 = { 45 cb [2] 31 d3 [2] 76 d1 [2] 31 c0 [2] 7f cc [2] 73 c6 [2] 64 cd [2] 7f 83 [2] 42 }

  condition:
    any of them
}