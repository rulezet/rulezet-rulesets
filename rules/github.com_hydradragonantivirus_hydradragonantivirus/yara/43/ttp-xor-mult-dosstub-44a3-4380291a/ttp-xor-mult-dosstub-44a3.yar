rule TTP_XOR_MULT_DOSStub_44a3 {
  strings:
    $key_44a3 = { 10 cb [2] 64 d3 [2] 23 d1 [2] 64 c0 [2] 2a cc [2] 26 c6 [2] 31 cd [2] 2a 83 [2] 17 }

  condition:
    any of them
}