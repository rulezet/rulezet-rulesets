rule TTP_XOR_MULT_DOSStub_4ea3 {
  strings:
    $key_4ea3 = { 1a cb [2] 6e d3 [2] 29 d1 [2] 6e c0 [2] 20 cc [2] 2c c6 [2] 3b cd [2] 20 83 [2] 1d }

  condition:
    any of them
}