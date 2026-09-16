rule TTP_XOR_MULT_DOSStub_78a3 {
  strings:
    $key_78a3 = { 2c cb [2] 58 d3 [2] 1f d1 [2] 58 c0 [2] 16 cc [2] 1a c6 [2] 0d cd [2] 16 83 [2] 2b }

  condition:
    any of them
}