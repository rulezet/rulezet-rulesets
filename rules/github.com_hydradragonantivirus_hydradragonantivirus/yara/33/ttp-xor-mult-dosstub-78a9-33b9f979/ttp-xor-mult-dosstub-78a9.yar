rule TTP_XOR_MULT_DOSStub_78a9 {
  strings:
    $key_78a9 = { 2c c1 [2] 58 d9 [2] 1f db [2] 58 ca [2] 16 c6 [2] 1a cc [2] 0d c7 [2] 16 89 [2] 2b }

  condition:
    any of them
}