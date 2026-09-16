rule TTP_XOR_MULT_DOSStub_1fa3 {
  strings:
    $key_1fa3 = { 4b cb [2] 3f d3 [2] 78 d1 [2] 3f c0 [2] 71 cc [2] 7d c6 [2] 6a cd [2] 71 83 [2] 4c }

  condition:
    any of them
}