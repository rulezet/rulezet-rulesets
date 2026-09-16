rule TTP_XOR_MULT_DOSStub_20a3 {
  strings:
    $key_20a3 = { 74 cb [2] 00 d3 [2] 47 d1 [2] 00 c0 [2] 4e cc [2] 42 c6 [2] 55 cd [2] 4e 83 [2] 73 }

  condition:
    any of them
}